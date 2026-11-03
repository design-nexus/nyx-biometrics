//! SSH keys that live on a FIDO2 security key (OpenSSH's `ed25519-sk`). The private key
//! never leaves the security key: the file in `~/.ssh` is only a handle that's useless
//! without it, and every signature needs a touch (and the key's PIN with `--pin`).
//! Resident keys keep the handle on the security key too, so `ssh-key load` brings them to
//! a new computer. Nothing here copies keys into Nyx Passwords: its SSH agent serves the
//! keys kept in the vault, and these stay on the hardware.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::FAILURE
}

const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const SK_TYPES: [&str; 2] = ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"];

fn ssh_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".ssh")
}

/// A key name: what the file and the comment carry.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The `ssh-keygen` arguments for a new key named `name` in `dir`.
pub(crate) fn create_args(dir: &Path, name: &str, resident: bool, pin: bool) -> Option<Vec<String>> {
    if !valid_name(name) {
        return None;
    }
    let file = dir.join(format!("id_ed25519_sk_{name}"));
    let mut args: Vec<String> = vec![
        "-t".into(),
        "ed25519-sk".into(),
        "-f".into(),
        file.to_string_lossy().into_owned(),
        "-C".into(),
        format!("{name} (security key)"),
        // The handle is useless without the security key, so it needs no passphrase.
        "-N".into(),
        String::new(),
        "-O".into(),
        format!("application=ssh:nyx-{name}"),
    ];
    if resident {
        args.extend(["-O".into(), "resident".into()]);
    }
    if pin {
        args.extend(["-O".into(), "verify-required".into()]);
    }
    Some(args)
}

/// One security-key SSH key found in `~/.ssh`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SkKey {
    pub file: String,
    pub kind: String,
    pub comment: String,
}

pub(crate) fn parse_pub(file: &str, line: &str) -> Option<SkKey> {
    let mut parts = line.split_whitespace();
    let kind = parts.next()?;
    if !SK_TYPES.contains(&kind) {
        return None;
    }
    parts.next()?;
    let comment: String = parts.collect::<Vec<_>>().join(" ").chars().filter(|c| !c.is_control()).collect();
    Some(SkKey {
        file: file.to_string(),
        kind: if kind.starts_with("sk-ssh-ed25519") { "ed25519-sk" } else { "ecdsa-sk" }.into(),
        comment,
    })
}

pub(crate) fn keys(dir: &Path) -> Vec<SkKey> {
    let mut out: Vec<SkKey> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".pub")?.to_string();
            let text = std::fs::read_to_string(e.path()).ok()?;
            parse_pub(&stem, text.lines().next()?)
        })
        .collect();
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

pub fn list() -> ExitCode {
    let found = keys(&ssh_dir());
    if found.is_empty() {
        println!("No SSH keys on a security key yet. Make one with: nyx-authctl ssh-key create NAME");
    }
    for k in found {
        println!("{}  {}  {}", k.file, k.kind, k.comment);
    }
    ExitCode::SUCCESS
}

/// `create [NAME] [--no-resident] [--pin]`; asks for the name when it's missing.
pub fn create(rest: &[&str]) -> ExitCode {
    let mut name = None;
    let (mut resident, mut pin) = (true, false);
    for a in rest {
        match *a {
            "--no-resident" => resident = false,
            "--pin" => pin = true,
            n if name.is_none() && !n.starts_with('-') => name = Some(n.to_string()),
            other => return fail(format!("Unknown option {other}")),
        }
    }
    let name = match name {
        Some(n) => n,
        None => {
            print!("Name for the new key (letters, digits, - and _): ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                return fail("No name given.");
            }
            line.trim().to_string()
        }
    };
    let dir = ssh_dir();
    let Some(args) = create_args(&dir, &name, resident, pin) else {
        return fail("Use up to 32 letters, digits, - or _ for the name.");
    };
    if dir.join(format!("id_ed25519_sk_{name}")).exists() {
        return fail(format!("~/.ssh/id_ed25519_sk_{name} already exists. Pick another name."));
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return fail("Can't create ~/.ssh.");
    }
    let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    println!("Plug in the security key and touch it when it blinks{}.", if pin { " (it asks for its PIN first)" } else { "" });
    match Command::new(SSH_KEYGEN).args(&args).status() {
        Ok(s) if s.success() => {
            println!("\nMade ~/.ssh/id_ed25519_sk_{name}. Add ~/.ssh/id_ed25519_sk_{name}.pub to the servers you use.");
            if resident {
                println!("It's also kept on the security key: on another computer, nyx-authctl ssh-key load.");
            }
            ExitCode::SUCCESS
        }
        _ => fail("ssh-keygen didn't make the key. Is the security key plugged in?"),
    }
}

/// Brings the resident keys on a plugged-in security key into `~/.ssh`.
pub fn load() -> ExitCode {
    let dir = ssh_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return fail("Can't create ~/.ssh.");
    }
    println!("Plug in the security key; it may ask for its PIN.");
    match Command::new(SSH_KEYGEN).arg("-K").current_dir(&dir).stdin(Stdio::inherit()).status() {
        Ok(s) if s.success() => list(),
        _ => fail("No keys came back. Is the security key plugged in, and were they made as resident keys?"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain() {
        assert!(valid_name("github"));
        assert!(valid_name("work_laptop-2"));
        assert!(!valid_name(""));
        assert!(!valid_name("../x"));
        assert!(!valid_name("a b"));
        assert!(!valid_name(&"x".repeat(33)));
    }

    #[test]
    fn create_asks_openssh_for_a_hardware_key() {
        let a = create_args(Path::new("/home/u/.ssh"), "github", true, true).unwrap();
        assert_eq!(&a[..4], ["-t", "ed25519-sk", "-f", "/home/u/.ssh/id_ed25519_sk_github"]);
        let joined = a.join(" ");
        assert!(joined.contains("-O resident") && joined.contains("-O verify-required"), "{joined}");
        assert!(joined.contains("-O application=ssh:nyx-github"));
        let b = create_args(Path::new("/home/u/.ssh"), "github", false, false).unwrap().join(" ");
        assert!(!b.contains("resident") && !b.contains("verify-required"));
        assert!(create_args(Path::new("/home/u/.ssh"), "../../etc", true, false).is_none());
    }

    #[test]
    fn lists_only_security_key_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), "ssh-ed25519 AAAA ken@hades\n").unwrap();
        std::fs::write(
            dir.path().join("id_ed25519_sk_github.pub"),
            "sk-ssh-ed25519@openssh.com AAAAGnNr github (security key)\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("id_ecdsa_sk_rk.pub"), "sk-ecdsa-sha2-nistp256@openssh.com AAAA\n").unwrap();
        let found = keys(dir.path());
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[1],
            SkKey { file: "id_ed25519_sk_github".into(), kind: "ed25519-sk".into(), comment: "github (security key)".into() }
        );
        assert_eq!(found[0].kind, "ecdsa-sk");
    }
}

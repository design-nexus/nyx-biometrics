//! nyx-auth-helper: the only part of Nyx Biometrics that writes system files.
//!
//! Run through pkexec, one polkit action per verb:
//!
//!   nyx-auth-helper keys-add primary|backup NAME     (pamu2fcfg output on stdin)
//!   nyx-auth-helper keys-remove ID
//!   nyx-auth-helper keys-rename ID primary|backup NAME
//!   nyx-auth-helper keys-import-omarchy
//!   nyx-auth-helper pam-apply SURFACE FINGERPRINT [migrate-omarchy]   (policy.toml on stdin)
//!   nyx-auth-helper pam-confirm ID
//!   nyx-auth-helper pam-restore [ID]
//!   nyx-auth-helper --version
//!
//! The user is always PKEXEC_UID's; nothing in the arguments can name another account.
//!
//! `pam-rollback ID` is run by the systemd timer `pam-apply` arms, as root without pkexec.
//! It can only put a snapshot back.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use nyx_auth_helper::keys::Store;
use nyx_auth_helper::{HELPER_VERSION, LOG_FILE, fsx, today};
use nyx_auth_hw::u2f::{Role, valid_user};

const MAX_STDIN: u64 = 4096;

mod pam_cmd;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("{HELPER_VERSION}");
        return ExitCode::SUCCESS;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("nyx-auth-helper must run through pkexec");
        return ExitCode::from(126);
    }
    if let [verb, id] = args.as_slice()
        && verb == "pam-rollback"
    {
        let result = pam_cmd::rollback(id);
        log("root", "pam-rollback", &result);
        return finish(result);
    }
    let user = match caller() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(126);
        }
    };
    let verb = args.first().map(String::as_str).unwrap_or("");
    let result = run(&user, &args);
    log(&user, verb, &result);
    finish(result)
}

fn finish(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(msg) => {
            if !msg.is_empty() {
                println!("{msg}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// The account polkit authenticated, from PKEXEC_UID only.
fn caller() -> Result<String, String> {
    let uid: libc::uid_t =
        std::env::var("PKEXEC_UID").ok().and_then(|v| v.parse().ok()).ok_or("nyx-auth-helper must run through pkexec")?;
    if uid == 0 {
        return Err("refusing to manage root's sign-in methods".into());
    }
    // SAFETY: getpwuid returns static storage or null, read immediately.
    let name = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return Err("unknown user".into());
        }
        CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    };
    if !valid_user(&name) {
        return Err("unsupported user name".into());
    }
    Ok(name)
}

fn role(arg: &str) -> Result<Role, String> {
    match arg {
        "primary" => Ok(Role::Primary),
        "backup" => Ok(Role::Backup),
        _ => Err("the role must be primary or backup".into()),
    }
}

fn run(user: &str, args: &[String]) -> Result<String, String> {
    let store = Store::system();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keys-add", r, name] => {
            let mut input = String::new();
            std::io::stdin().take(MAX_STDIN).read_to_string(&mut input).map_err(|e| e.to_string())?;
            let id = store.add(user, &input, name, role(r)?, &today()).map_err(|e| e.to_string())?;
            Ok(id)
        }
        ["keys-remove", id] => store.remove(user, id).map(|_| String::new()).map_err(|e| e.to_string()),
        ["keys-rename", id, r, name] => store.rename(user, id, name, role(r)?).map(|_| String::new()).map_err(|e| e.to_string()),
        ["keys-import-omarchy"] => store.import_omarchy(user, &today()).map(|n| n.to_string()).map_err(|e| e.to_string()),
        ["pam-apply", surface, fp, rest @ ..] => {
            let migrate = match rest {
                [] => false,
                ["migrate-omarchy"] => true,
                _ => return Err("unknown option".into()),
            };
            let mut policy = String::new();
            std::io::stdin().take(64 * 1024).read_to_string(&mut policy).map_err(|e| e.to_string())?;
            pam_cmd::apply(user, surface, fp, migrate, &policy)
        }
        ["pam-confirm", id] => pam_cmd::confirm(id),
        ["pam-restore"] => pam_cmd::restore(None),
        ["pam-restore", id] => pam_cmd::restore(Some(id)),
        _ => Err("unknown command".into()),
    }
}

/// One JSON line per request: who, what, whether it worked. Never key material.
fn log(user: &str, verb: &str, result: &Result<String, String>) {
    let verb = match verb {
        "keys-add"
        | "keys-remove"
        | "keys-rename"
        | "keys-import-omarchy"
        | "pam-apply"
        | "pam-confirm"
        | "pam-restore"
        | "pam-rollback" => verb,
        _ => "unknown",
    };
    let line = serde_json::json!({
        "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "user": user,
        "verb": verb,
        "ok": result.is_ok(),
    });
    let path = std::path::Path::new(LOG_FILE);
    if let Some(dir) = path.parent()
        && fsx::ensure_dir(dir).is_ok()
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

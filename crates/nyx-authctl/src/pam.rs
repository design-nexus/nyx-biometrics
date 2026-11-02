//! `nyx-authctl pam`: preview, apply with a live test, confirm, restore.

use std::io::{BufRead, Write};
use std::process::{Command, ExitCode, Stdio};

use nyx_auth_core::Surface;
use nyx_auth_helper::INSTALL_PATH;
use nyx_auth_helper::pam::{self, ROLLBACK_SECS, Root};
use nyx_auth_hw::SystemRunner;
use nyx_auth_hw::report::{Paths, Report};
use nyx_auth_pam::pamtest::{self, Prompt};
use nyx_auth_pam::{Modules, diff};

const PKEXEC: &str = "/usr/bin/pkexec";
const SUDO: &str = "/usr/bin/sudo";

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::FAILURE
}

#[derive(Default)]
struct Flags {
    migrate: bool,
    /// Approved elsewhere (for example in a chat with an agent): don't ask again.
    yes: bool,
    /// Test with the face alone: answer "yes" to the face prompt and never send a password.
    face: bool,
}

fn parse(args: &[&str]) -> Result<(Surface, Flags), ExitCode> {
    let mut surface = None;
    let mut flags = Flags::default();
    for a in args {
        match *a {
            "--migrate-omarchy" => flags.migrate = true,
            "--yes" => flags.yes = true,
            "--face" => flags.face = true,
            s => surface = pam::surface_key(s),
        }
    }
    surface.map(|s| (s, flags)).ok_or_else(|| fail("Name a surface: login, lock-screen, sudo or polkit."))
}

fn policy_text() -> Result<String, ExitCode> {
    match std::fs::read_to_string(crate::policy_path()) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(nyx_auth_core::PolicySet::default().to_toml()),
        Err(e) => Err(fail(e)),
    }
}

struct Prepared {
    policy: String,
    fingerprint: String,
    changes: Vec<nyx_auth_pam::generate::FileChange>,
}

fn prepare(surface: Surface, migrate: bool) -> Result<Prepared, ExitCode> {
    let policy = policy_text()?;
    let report = Report::collect(&SystemRunner, &Paths::system(), &crate::user());
    let modules = Modules { migrate_omarchy: migrate, ..Modules::system(report.face.as_ref().map(|c| c.backend)) };
    let root = Root::system();
    let all = pam::prepare(&root, &policy, surface, &report.inventory(), &modules).map_err(|e| {
        let hint = if matches!(e, pam::PamError::Generate(ref m) if m.contains("Omarchy")) {
            "\nAdd --migrate-omarchy to move Omarchy's lines into Nyx Biometrics."
        } else {
            ""
        };
        fail(format!("{e}{hint}"))
    })?;
    Ok(Prepared { policy, fingerprint: pam::fingerprint(&all), changes: pam::effective(&root, &all) })
}

fn show(p: &Prepared) {
    if p.changes.is_empty() {
        println!("Nothing would change.");
        return;
    }
    let root = Root::system();
    for c in &p.changes {
        let current = std::fs::read_to_string(root.at(&c.path)).unwrap_or_default();
        match &c.contents {
            Some(new) if current.is_empty() => println!("\n=== {} (new file)\n{}", c.path, diff::lines("", new)),
            Some(new) => println!("\n=== {}\n{}", c.path, diff::lines(&current, new)),
            None => println!("\n=== {} (removed)", c.path),
        }
    }
    println!("All checks passed. Change ID {}.", p.fingerprint);
}

pub fn preview(args: &[&str]) -> ExitCode {
    let Ok((surface, flags)) = parse(args) else { return ExitCode::from(2) };
    match prepare(surface, flags.migrate) {
        Ok(p) => {
            show(&p);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn ask(question: &str) -> bool {
    print!("{question} ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == "yes"
}

fn helper_capture(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(PKEXEC)
        .arg(INSTALL_PATH)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(input.as_bytes());
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
        Some(126 | 127) => Err("Cancelled.".into()),
        _ => Err("The helper refused; see the message above.".into()),
    }
}

fn service(surface: Surface) -> &'static str {
    match surface {
        Surface::Sudo => "sudo",
        Surface::Polkit => "polkit-1",
        Surface::Login => "sddm",
        _ => "omarchy-lock-face",
    }
}

/// One PAM conversation that only accepts the face. The first prompt selects one face
/// attempt: an empty answer where Irlume runs on demand (login, lock screen), "yes" at its
/// consent prompt (sudo, polkit). Any later prompt means the face didn't do it.
fn face_test(surface: Surface) -> Result<(), String> {
    let select = if matches!(surface, Surface::Login | Surface::LockScreen) { "" } else { "yes" };
    let mut asked = false;
    println!("Look at the camera.");
    pamtest::authenticate(service(surface), &crate::user(), |p| match p {
        Prompt::Secret(_) | Prompt::Visible(_) if !asked => {
            asked = true;
            Some(select.into())
        }
        Prompt::Secret(_) | Prompt::Visible(_) => None,
        Prompt::Info(t) => {
            println!("{t}");
            None
        }
    })
}

/// Authenticate against the changed service, as it will be used.
fn live_test(surface: Surface, face: bool) -> Result<(), String> {
    // The lock screen's only Nyx service is the face; Omarchy owns its password service.
    // A glance away during the first attempt shouldn't throw the change away, so try twice.
    if face || surface == Surface::LockScreen {
        return face_test(surface).or_else(|_| {
            println!("Not yet. Once more:");
            face_test(surface)
        });
    }
    match surface {
        Surface::Sudo => {
            let _ = Command::new(SUDO).arg("-k").status();
            // With Irlume's consent prompt on, its "use your face?" question arrives as sudo's
            // ordinary password prompt; name both answers.
            let ok = Command::new(SUDO)
                .args(["-p", "Look at the camera (type yes first if asked), or type your password: ", "/usr/bin/true"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok { Ok(()) } else { Err("sudo didn't accept".into()) }
        }
        _ => pamtest::authenticate(service(surface), &crate::user(), |p| match p {
            Prompt::Secret(t) => pamtest::read_secret(&format!("{t} ")),
            Prompt::Visible(t) => {
                print!("{t} ");
                let _ = std::io::stdout().flush();
                let mut l = String::new();
                std::io::stdin().lock().read_line(&mut l).ok()?;
                Some(l.trim_end().to_string())
            }
            Prompt::Info(t) => {
                println!("{t}");
                None
            }
        }),
    }
}

pub fn apply(args: &[&str]) -> ExitCode {
    let Ok((surface, flags)) = parse(args) else { return ExitCode::from(2) };
    let migrate = flags.migrate;
    let p = match prepare(surface, migrate) {
        Ok(p) => p,
        Err(code) => return code,
    };
    show(&p);
    if p.changes.is_empty() {
        return ExitCode::SUCCESS;
    }
    println!(
        "\nBefore applying, open a root shell in another terminal (sudo -s) and leave it open.\n\
         After applying you'll be asked to sign in once to prove it works. If you don't, or it\n\
         fails, the change is undone automatically after {ROLLBACK_SECS} seconds."
    );
    if !flags.yes && !ask("\nType yes to apply:") {
        return fail("Nothing changed.");
    }
    let mut helper_args = vec!["pam-apply", surface.key(), p.fingerprint.as_str()];
    if migrate {
        helper_args.push("migrate-omarchy");
    }
    let id = match helper_capture(&helper_args, Some(&p.policy)) {
        Ok(id) if id == "nothing to change" => {
            println!("Nothing to change.");
            return ExitCode::SUCCESS;
        }
        Ok(id) => id,
        Err(e) => return fail(e),
    };
    println!("\nApplied (snapshot {id}). Now sign in once with the new setup.");
    if surface == Surface::Polkit && !flags.face {
        println!("To use your face: type  yes  in the password field and look at the camera.");
    }
    match live_test(surface, flags.face) {
        Ok(()) => {}
        Err(e) => {
            return fail(format!(
                "\nThe test failed ({e}). Not confirming: the change is undone automatically within {ROLLBACK_SECS} seconds,\n\
                 or now with: nyx-authctl pam restore {id}"
            ));
        }
    }
    println!("\nThat worked. Confirming (this is also an administrator prompt):");
    match helper_capture(&["pam-confirm", &id], None) {
        Ok(_) => {
            println!("Kept. Undo any time with: nyx-authctl pam restore {id}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("Couldn't confirm ({e}); the change will be undone automatically.")),
    }
}

pub fn test(args: &[&str]) -> ExitCode {
    let Ok((surface, flags)) = parse(args) else { return ExitCode::from(2) };
    match live_test(surface, flags.face) {
        Ok(()) => {
            println!("Accepted.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("Refused: {e}")),
    }
}

pub fn restore(id: Option<&str>) -> ExitCode {
    let mut args = vec!["pam-restore"];
    args.extend(id);
    match helper_capture(&args, None) {
        Ok(id) => {
            println!("Restored the files from snapshot {id}.");
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!(
            "{e}\nFrom a root shell or a TTY: {INSTALL_PATH} is run by root as `pam-rollback ID`, or copy the files back from /var/lib/nyx-biometrics/pam-backups/ID."
        )),
    }
}

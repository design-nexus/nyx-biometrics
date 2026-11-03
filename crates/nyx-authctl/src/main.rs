use std::ffi::CStr;
use std::path::PathBuf;
use std::process::ExitCode;

use nyx_auth_core::{PolicySet, Surface};
use nyx_auth_hw::SystemRunner;
use nyx_auth_hw::report::{Paths, Report, Status};

mod enroll;
mod pam;
mod ssh;
mod status;

const USAGE: &str = "Usage: nyx-authctl <command>

  doctor [--json]       What sign-in hardware this computer has and what's set up
  policy show           The current policy, by surface
  policy check          Check the policy against this computer's hardware
  policy recommend      The policy setup would suggest for this hardware
  policy set SURFACE METHOD on|off
                        Turn face, fingerprint or security-key on or off for login,
                        lock-screen, sudo, polkit, vault or app-action
  status --json         Everything Nyx Settings shows, as JSON

  keys list                       Registered security keys
  keys add NAME [--backup] [--pin]
                                  Register the plugged-in key (touch it when it blinks).
                                  --pin also asks for its PIN every time it's used
  keys rename ID NAME [--backup]  Rename a key or change its role
  keys remove ID                  Stop accepting a key
  keys import-omarchy             Use the keys Omarchy's FIDO2 setup registered

  finger list                     Enrolled fingers
  finger enroll [FINGER]          Enroll a finger (default right-index-finger)
  finger remove FINGER            Delete an enrolled finger

  face enroll                     Enroll your face with the backend for this camera
  face manage                     Open the backend's own manager

  pam preview SURFACE [--migrate-omarchy]
                                  Show exactly what would change for login, lock-screen,
                                  sudo or polkit, and run every check. Needs no root
  pam apply SURFACE [--migrate-omarchy] [--yes] [--face]
                                  Apply it, test it with one sign-in, and keep it only if
                                  that works; otherwise it's undone after 2 minutes.
                                  --face tests with your face alone, never the password
  pam test SURFACE [--face]       Sign in once against a surface's current setup
  pam restore [ID]                Put back the files from before a change (newest by default)

  login-theme on|off|status       Use the Nyx login screen (Halo for the face) or
                                  Omarchy's own
  ssh-key list                    SSH keys that live on a security key
  ssh-key create [NAME] [--pin] [--no-resident]
                                  Make one (touch the key; --pin asks for its PIN each
                                  use). Kept on the key too, unless --no-resident
  ssh-key load                    Bring the keys kept on a security key into ~/.ssh

  broker test                     Ask the sign-in broker (nyx-authd) to confirm it's you,
                                  as a Nyx app would. Grants nothing
  helper status                   Whether the root helper is installed and current
  helper install                  Install the root helper and its polkit actions (run with sudo)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["doctor"] => doctor(false),
        ["doctor", "--json"] => doctor(true),
        ["policy", "show"] => policy_show(),
        ["policy", "check"] => policy_check(),
        ["policy", "recommend"] => policy_recommend(),
        ["policy", "set", surface, method, on] => status::policy_set(surface, method, on),
        ["status", "--json"] => status::status(),
        ["keys", "list"] => enroll::keys_list(&user()),
        ["keys", "add", rest @ ..] => enroll::keys_add(rest),
        ["keys", "rename", id, rest @ ..] => enroll::keys_rename(id, rest),
        ["keys", "remove", id] => enroll::helper(&["keys-remove", id], None),
        ["keys", "import-omarchy"] => enroll::helper(&["keys-import-omarchy"], None),
        ["finger", "list"] => enroll::finger_list(&user()),
        ["finger", "enroll"] => enroll::finger_enroll(&user(), "right-index-finger"),
        ["finger", "enroll", finger] => enroll::finger_enroll(&user(), finger),
        ["finger", "remove", finger] => enroll::finger_remove(&user(), finger),
        ["face", "enroll"] => enroll::face(&report(), false),
        ["face", "manage"] => enroll::face(&report(), true),
        ["pam", "preview", rest @ ..] => pam::preview(rest),
        ["pam", "apply", rest @ ..] => pam::apply(rest),
        ["pam", "test", rest @ ..] => pam::test(rest),
        ["pam", "restore"] => pam::restore(None),
        ["pam", "restore", id] => pam::restore(Some(id)),
        ["login-theme", "on"] => enroll::helper(&["login-theme", "on"], None),
        ["login-theme", "off"] => enroll::helper(&["login-theme", "off"], None),
        ["login-theme", "status"] => login_theme_status(),
        ["ssh-key", "list"] => ssh::list(),
        ["ssh-key", "create", rest @ ..] => ssh::create(rest),
        ["ssh-key", "load"] => ssh::load(),
        ["broker", "test"] => broker_test(),
        ["helper", "status"] => enroll::helper_status(),
        ["helper", "install"] => enroll::helper_install(),
        ["help" | "--help" | "-h"] => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// The calling user's name from the password database, not the environment.
pub(crate) fn user() -> String {
    // SAFETY: getpwuid returns a pointer into static storage or null; it's read before any
    // other call that could overwrite it.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return String::new();
        }
        CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    }
}

pub(crate) fn report() -> Report {
    Report::collect(&SystemRunner, &Paths::system(), &user())
}

fn doctor(json: bool) -> ExitCode {
    let report = report();
    let findings = report.findings();
    if json {
        let doc = serde_json::json!({ "report": report, "findings": findings, "inventory": report.inventory() });
        println!("{}", serde_json::to_string_pretty(&doc).expect("report serializes"));
        return ExitCode::SUCCESS;
    }
    let mut area = "";
    for f in &findings {
        if f.area != area {
            area = f.area;
            println!("\n{}", heading(area));
        }
        let mark = match f.status {
            Status::Ok => "ok  ",
            Status::Info => "    ",
            Status::Warn => "warn",
            Status::Missing => "--  ",
            Status::Error => "err ",
        };
        println!("  {mark} {}", f.message);
    }
    let inv = report.inventory();
    println!("\nUsable now");
    println!("  Password");
    if let Some(face) = inv.face {
        println!("  Face ({:?}{})", face.camera, if face.liveness { ", with liveness" } else { "" });
    }
    if inv.fingerprint {
        println!("  Fingerprint");
    }
    for k in &inv.keys {
        println!("  Security key “{}”{}", k.name, if k.verification { " (PIN)" } else { "" });
    }
    ExitCode::SUCCESS
}

fn heading(area: &str) -> &'static str {
    match area {
        "face" => "Face",
        "fingerprint" => "Fingerprint",
        "security-key" => "Security keys",
        "tpm" => "TPM",
        _ => "Other",
    }
}

pub(crate) fn policy_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    base.join("nyx/auth/policy.toml")
}

fn load_policy() -> Result<PolicySet, String> {
    match std::fs::read_to_string(policy_path()) {
        Ok(text) => PolicySet::from_toml(&text).map_err(|e| format!("{}: {e}", policy_path().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PolicySet::default()),
        Err(e) => Err(format!("{}: {e}", policy_path().display())),
    }
}

fn policy_show() -> ExitCode {
    match load_policy() {
        Ok(p) => {
            print!("{}", p.to_toml());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn policy_check() -> ExitCode {
    let policy = match load_policy() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let inv = report().inventory();
    let mut ok = true;
    for s in Surface::ALL {
        match policy.get(s).plan(s, &inv) {
            Ok(plan) => {
                let alts: Vec<String> = plan
                    .alternatives
                    .iter()
                    .map(|a| a.iter().map(|m| m.kind().label()).collect::<Vec<_>>().join(" + "))
                    .collect();
                println!("ok    {}: {}", s.label(), alts.join(", "));
                for k in plan.unavailable {
                    println!("        {} isn't available right now", k.label());
                }
            }
            Err(errors) => {
                ok = false;
                println!("error {}:", s.label());
                for e in errors {
                    println!("        {e}");
                }
            }
        }
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn policy_recommend() -> ExitCode {
    print!("{}", PolicySet::recommended(&report().inventory()).to_toml());
    ExitCode::SUCCESS
}

fn login_theme_status() -> ExitCode {
    use nyx_auth_helper::login_theme;
    let root = nyx_auth_helper::pam::Root::system();
    match (login_theme::installed(&root), login_theme::chosen(&root)) {
        (true, true) => println!("On: the login screen shows Halo for the face."),
        (true, false) => println!("Off: Omarchy's login screen. Turn on with: nyx-authctl login-theme on"),
        (false, _) => println!("Not installed. Run: sudo nyx-authctl helper install"),
    }
    ExitCode::SUCCESS
}

/// One request through the broker, as Nyx apps make them (the broker's owner checked
/// first), to check the whole path.
fn broker_test() -> ExitCode {
    use nyx_auth_proto::{Outcome, Request, Surface};
    let run = async {
        let conn = zbus::Connection::session().await?;
        nyx_auth_proto::connect(&conn)
            .await?
            .authenticate(Request {
                action: "io.github.design_nexus.nyx.authctl.test".into(),
                purpose: "Test the sign-in broker (grants nothing)".into(),
                surface: Surface::AppAction,
                grant_secs: 0,
            })
            .await
    };
    println!("Confirm it's you when the prompt appears.");
    let reply = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt.block_on(run),
        Err(e) => return fail_msg(e),
    };
    match reply {
        Ok(r) if r.outcome == Outcome::Granted => {
            println!("Granted.");
            ExitCode::SUCCESS
        }
        Ok(r) => {
            println!("Not granted: {:?}.", r.outcome);
            ExitCode::FAILURE
        }
        Err(e) => fail_msg(format!("The broker didn't answer: {e}")),
    }
}

fn fail_msg(e: impl std::fmt::Display) -> ExitCode {
    eprintln!("{e}");
    ExitCode::FAILURE
}

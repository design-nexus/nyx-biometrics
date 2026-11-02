//! Enrollment. Each method's own tool does the enrolling and shows its own guidance; this
//! module picks the right tool, passes results to the root helper, and refuses unknown input.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use nyx_auth_helper::{HELPER_VERSION, INSTALL_PATH, POLICY, POLICY_FILE};
use nyx_auth_hw::face::Backend;
use nyx_auth_hw::report::Report;
use nyx_auth_hw::u2f::{self, AuthFile, Names};

const PKEXEC: &str = "/usr/bin/pkexec";
const PAMU2FCFG: &str = "/usr/bin/pamu2fcfg";
const FPRINTD_ENROLL: &str = "/usr/bin/fprintd-enroll";
const FPRINTD_LIST: &str = "/usr/bin/fprintd-list";
const FPRINTD_DELETE: &str = "/usr/bin/fprintd-delete";

const FINGERS: &[&str] = &[
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
];

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::FAILURE
}

fn status(cmd: &mut Command) -> ExitCode {
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(e) => fail(e),
    }
}

fn need(program: &str, package: &str) -> Result<(), ExitCode> {
    if Path::new(program).is_file() {
        Ok(())
    } else {
        Err(fail(format!("{program} isn't installed. Install the {package} package first.")))
    }
}

/// Run the root helper through pkexec, optionally feeding it stdin.
pub fn helper(args: &[&str], stdin: Option<&str>) -> ExitCode {
    if let Err(code) = need(INSTALL_PATH, "Nyx Biometrics helper (nyx-authctl helper install)") {
        return code;
    }
    let mut cmd = Command::new(PKEXEC);
    cmd.arg(INSTALL_PATH).args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(input.as_bytes());
    }
    match child.wait() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) if matches!(s.code(), Some(126 | 127)) => fail("Cancelled."),
        Ok(_) => ExitCode::FAILURE,
        Err(e) => fail(e),
    }
}

pub fn keys_list(user: &str) -> ExitCode {
    let file = std::fs::read_to_string(u2f::AUTHFILE).ok().and_then(|t| AuthFile::parse(&t).ok()).unwrap_or_default();
    let names = std::fs::read_to_string(Path::new(u2f::NAMES_DIR).join(format!("{user}.toml")))
        .ok()
        .and_then(|t| Names::parse(&t).ok())
        .unwrap_or_default();
    let creds = file.credentials(user);
    if creds.is_empty() {
        println!("No security keys registered.");
    }
    for (i, c) in creds.iter().enumerate() {
        let meta = names.name_of(c);
        let name = meta.map(|n| n.name.clone()).unwrap_or_else(|| format!("Security key {}", i + 1));
        let role = match meta.map(|n| n.role) {
            Some(u2f::Role::Backup) => "backup",
            _ => "primary",
        };
        let pin = if c.verification() { ", PIN" } else { "" };
        println!("{}  {name} ({role}{pin})", c.id());
    }
    ExitCode::SUCCESS
}

pub fn keys_add(rest: &[&str]) -> ExitCode {
    let mut name = None;
    let mut backup = false;
    let mut pin = false;
    for arg in rest {
        match *arg {
            "--backup" => backup = true,
            "--pin" => pin = true,
            a if a.starts_with("--") => return fail(format!("unknown option {a}")),
            a if name.is_none() => name = Some(a),
            _ => return fail("give the key's name once, in quotes if it has spaces"),
        }
    }
    let Some(name) = name else { return fail("give the key a name, such as \"Primary YubiKey\"") };
    if let Err(code) = need(PAMU2FCFG, "pam-u2f") {
        return code;
    }
    eprintln!("Touch your security key when it blinks{}.", if pin { " (it will ask for its PIN first)" } else { "" });
    let mut cmd = Command::new(PAMU2FCFG);
    if pin {
        cmd.arg("--pin-verification");
    }
    let out = match cmd.stdin(Stdio::inherit()).stderr(Stdio::inherit()).output() {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    if !out.status.success() {
        return fail("The key wasn't registered. Check that it's plugged in, then try again.");
    }
    let line = String::from_utf8_lossy(&out.stdout).into_owned();
    helper(&["keys-add", if backup { "backup" } else { "primary" }, name], Some(&line))
}

pub fn keys_rename(id: &str, rest: &[&str]) -> ExitCode {
    let (backup, names): (Vec<&str>, Vec<&str>) = rest.iter().partition(|a| **a == "--backup");
    let [name] = names.as_slice() else { return fail("give one new name, in quotes if it has spaces") };
    helper(&["keys-rename", id, if backup.is_empty() { "primary" } else { "backup" }, name], None)
}

fn valid_finger(finger: &str) -> Result<(), ExitCode> {
    if FINGERS.contains(&finger) { Ok(()) } else { Err(fail(format!("unknown finger. Use one of: {}", FINGERS.join(", ")))) }
}

pub fn finger_list(user: &str) -> ExitCode {
    if let Err(code) = need(FPRINTD_LIST, "fprintd") {
        return code;
    }
    status(Command::new(FPRINTD_LIST).arg(user))
}

pub fn finger_enroll(user: &str, finger: &str) -> ExitCode {
    if let Err(code) = need(FPRINTD_ENROLL, "fprintd") {
        return code;
    }
    if let Err(code) = valid_finger(finger) {
        return code;
    }
    status(Command::new(FPRINTD_ENROLL).args(["-f", finger, user]))
}

pub fn finger_remove(user: &str, finger: &str) -> ExitCode {
    if let Err(code) = need(FPRINTD_DELETE, "fprintd") {
        return code;
    }
    if let Err(code) = valid_finger(finger) {
        return code;
    }
    status(Command::new(FPRINTD_DELETE).args([user, "-f", finger]))
}

pub fn face(report: &Report, manage: bool) -> ExitCode {
    let Some(choice) = &report.face else { return fail("No camera found.") };
    let probe = match choice.backend {
        Backend::Irlume => &report.irlume,
        Backend::Gaze => &report.gaze,
    };
    if !probe.installed {
        return fail(format!("{}. Install {} first.", choice.reason, choice.backend.label()));
    }
    let argv: &[&str] = match (choice.backend, manage) {
        (b, false) => b.enroll_command(),
        (Backend::Irlume, true) => &["/usr/bin/irlume", "tui"],
        (Backend::Gaze, true) => &["/usr/bin/gaze-gui"],
    };
    eprintln!("{}: {}", choice.backend.label(), choice.reason);
    status(Command::new(argv[0]).args(&argv[1..]))
}

pub fn helper_status() -> ExitCode {
    let installed = Command::new(INSTALL_PATH)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| v.trim().parse::<u32>().ok());
    let policy_ok = std::fs::read_to_string(POLICY_FILE).map(|p| p == POLICY).unwrap_or(false)
        && Path::new(nyx_auth_pam::generate::GATE).is_file();
    match (installed, policy_ok) {
        (Some(v), true) if v == HELPER_VERSION => {
            println!("Installed and current (version {v}).");
            ExitCode::SUCCESS
        }
        (None, _) => fail("Not installed. Run: sudo nyx-authctl helper install"),
        _ => fail("Out of date. Run: sudo nyx-authctl helper install"),
    }
}

/// Copy the helper and the gate that sit next to this binary into their root-owned
/// locations and install the polkit actions. Must be run as root, deliberately.
pub fn helper_install() -> ExitCode {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return fail("Run this with sudo.");
    }
    let Some(here) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) else {
        return fail("Can't find the directory nyx-authctl runs from.");
    };
    for name in ["nyx-auth-helper", "nyx-auth-gate"] {
        if !here.join(name).is_file() {
            return fail(format!("{} doesn't exist. Build it first.", here.join(name).display()));
        }
    }
    let install = |source: &Path, target: &str| -> std::io::Result<()> {
        let target = Path::new(target);
        let dir = target.parent().expect("absolute path");
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        let tmp = dir.join(".nyx-install.new");
        std::fs::copy(source, &tmp)?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        std::fs::rename(&tmp, target)
    };
    let result = (|| -> std::io::Result<()> {
        install(&here.join("nyx-auth-helper"), INSTALL_PATH)?;
        install(&here.join("nyx-auth-gate"), nyx_auth_pam::generate::GATE)?;
        let ptmp = Path::new(POLICY_FILE).with_extension("policy.new");
        std::fs::write(&ptmp, POLICY)?;
        std::fs::set_permissions(&ptmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        std::fs::rename(&ptmp, POLICY_FILE)
    })();
    match result {
        Ok(()) => {
            println!("Installed {INSTALL_PATH}, {} and {POLICY_FILE}.", nyx_auth_pam::generate::GATE);
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

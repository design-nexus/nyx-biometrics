//! `nyx-auth-gate`: decides, inside a PAM stack, whether to skip the next method.
//!
//! It exits 0 to **skip** (`[success=1 default=ignore]`), so a gate that can't run leaves
//! the stack as if it weren't there, and a skip never records a failure that could sink the
//! password. Anything it can't establish counts as a reason to skip.

use std::fs;
use std::path::Path;
use std::time::Duration;

use nyx_auth_hw::Runner;

pub const LOGINCTL: &str = "/usr/bin/loginctl";

/// Programs whose children are remote sessions.
const REMOTE_PARENTS: &[&str] =
    &["sshd", "sshd-session", "sshd-auth", "dropbear", "mosh-server", "in.telnetd", "telnetd", "xrdp", "xrdp-sesman", "rlogind"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Sensors built into the computer: face, fingerprint. Also skipped with the lid closed.
    BuiltIn,
    /// Anything that needs someone at this computer: security keys.
    Local,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "built-in" => Some(Kind::BuiltIn),
            "local" => Some(Kind::Local),
            _ => None,
        }
    }
}

/// What the gate found out. `None` is "couldn't tell".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    pub service: String,
    pub rhost: String,
    pub ancestors: Vec<String>,
    /// The PAM application's own login session is remote; `None` when it has none.
    pub caller_session_remote: Option<bool>,
    /// The user's display session is local, on a seat, and active.
    pub local_display: Option<bool>,
    pub lid_closed: bool,
    /// The person asked for their password instead (Nyx Prompt's "Use password").
    pub password_first: bool,
}

/// Nyx Prompt's marker for "use my password this time": in the user's runtime folder,
/// theirs, and fresh. Honoured for administrator prompts only, where the prompt asks.
pub const PASSWORD_FIRST: &str = "nyx-auth/password-first";
const PASSWORD_FIRST_FOR: Duration = Duration::from_secs(60);

/// Whether `uid`'s marker is there: a regular file they own (not a link), under a minute old.
pub fn password_first(runtime: &Path, uid: u32) -> bool {
    fresh_password_marker(&runtime.join(uid.to_string()).join(PASSWORD_FIRST), uid)
}

/// Also used for markers in private account directories provisioned by NixOS.
pub fn fresh_password_marker(path: &Path, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = fs::symlink_metadata(path) else { return false };
    m.file_type().is_file()
        && m.uid() == uid
        && m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age < PASSWORD_FIRST_FOR)
}

/// `Some(reason)` to skip.
pub fn decide(kind: Kind, ctx: &Context) -> Option<&'static str> {
    let rhost = ctx.rhost.trim().to_ascii_lowercase();
    if !matches!(rhost.as_str(), "" | "localhost" | "localhost.localdomain" | "127.0.0.1" | "::1") {
        return Some("remote host");
    }
    if ctx.ancestors.iter().any(|a| REMOTE_PARENTS.contains(&a.as_str())) {
        return Some("remote session");
    }
    // The login screen signs in someone who has no session yet: its helper belongs to no
    // audit session and the user has no display. SDDM only drives local seats, so its own
    // helper, started by the SDDM daemon, is someone at this computer.
    let greeter = ctx.service == "sddm"
        && ctx.ancestors.first().is_some_and(|a| a == "sddm-helper")
        && ctx.ancestors.iter().any(|a| a == "sddm");
    match ctx.caller_session_remote {
        Some(true) => return Some("remote session"),
        Some(false) => {}
        None if greeter => {}
        // The socket-activated polkit helper belongs to no session; for it the user's
        // display session below decides. Anything else without a session (cron, services)
        // isn't someone at the keyboard.
        None if ctx.service == "polkit-1" => {}
        None => return Some("no login session"),
    }
    if !greeter && ctx.local_display != Some(true) {
        return Some("no active local session");
    }
    if kind == Kind::BuiltIn && ctx.lid_closed {
        return Some("lid closed");
    }
    // Skipping only ever leaves the password, so it can't make signing in easier.
    if ctx.password_first && ctx.service == "polkit-1" {
        return Some("password asked for");
    }
    None
}

/// Process names from `pid`'s parent up to init, read from `proc`.
pub fn ancestors(proc: &Path, mut pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..64 {
        if pid <= 1 {
            break;
        }
        let exe = fs::read_link(proc.join(pid.to_string()).join("exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .or_else(|| fs::read_to_string(proc.join(pid.to_string()).join("comm")).ok().map(|s| s.trim().to_string()));
        if let Some(name) = exe {
            out.push(name.trim_end_matches(" (deleted)").to_string());
        }
        let Some(ppid) = fs::read_to_string(proc.join(pid.to_string()).join("stat")).ok().and_then(|s| parent_of(&s)) else {
            break;
        };
        pid = ppid;
    }
    out
}

/// The fourth field of `/proc/<pid>/stat`, after the parenthesised command name.
fn parent_of(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub fn lid_closed(proc: &Path) -> bool {
    let Ok(entries) = fs::read_dir(proc.join("acpi/button/lid")) else { return false };
    entries.filter_map(|e| e.ok()).any(|e| fs::read_to_string(e.path().join("state")).is_ok_and(|s| s.contains("closed")))
}

fn loginctl(runner: &dyn Runner, args: &[&str]) -> Option<String> {
    let out = runner.run(LOGINCTL, args, Duration::from_secs(2)).ok()?;
    out.success().then(|| out.stdout.trim().to_string())
}

/// The audit session of `pid` and whether logind calls it remote.
pub fn session_remote(proc: &Path, runner: &dyn Runner, pid: u32) -> Option<bool> {
    let id = fs::read_to_string(proc.join(pid.to_string()).join("sessionid")).ok()?;
    let id = id.trim();
    if id.is_empty() || id == "4294967295" || !id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match loginctl(runner, &["show-session", id, "-p", "Remote", "--value"])?.as_str() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Whether `user`'s display session is local, on a seat, and active.
pub fn local_display(runner: &dyn Runner, user: &str) -> Option<bool> {
    if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    let id = loginctl(runner, &["show-user", user, "-p", "Display", "--value"])?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Some(false);
    }
    let props = loginctl(runner, &["show-session", &id, "-p", "Remote", "-p", "Active", "-p", "Seat"])?;
    let get = |k: &str| props.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap_or("");
    Some(get("Remote") == "no" && get("Active") == "yes" && !get("Seat").is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyx_auth_hw::cmd::{FakeRunner, Output};

    fn local() -> Context {
        Context {
            service: "sudo".into(),
            ancestors: vec!["sudo".into(), "bash".into(), "alacritty".into(), "systemd".into()],
            caller_session_remote: Some(false),
            local_display: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn password_first_skips_methods_in_administrator_prompts_only() {
        let polkit = Context { service: "polkit-1".into(), password_first: true, ..local() };
        assert_eq!(decide(Kind::BuiltIn, &polkit), Some("password asked for"));
        assert_eq!(decide(Kind::Local, &polkit), Some("password asked for"));
        let sudo = Context { password_first: true, ..local() };
        assert_eq!(decide(Kind::BuiltIn, &sudo), None);
    }

    #[test]
    fn password_first_marker_is_the_users_own_and_fresh() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        assert!(!password_first(dir.path(), uid));
        let marker = dir.path().join(uid.to_string()).join(PASSWORD_FIRST);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "").unwrap();
        assert!(password_first(dir.path(), uid));
        assert!(!password_first(dir.path(), uid + 1), "someone else's folder");
        // A link isn't the marker.
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(dir.path(), &marker).unwrap();
        assert!(!password_first(dir.path(), uid));
        // An old one has expired.
        std::fs::remove_file(&marker).unwrap();
        std::fs::write(&marker, "").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(120);
        std::fs::File::options().write(true).open(&marker).unwrap().set_modified(old).unwrap();
        assert!(!password_first(dir.path(), uid));
    }

    #[test]
    fn local_terminal_runs_methods() {
        assert_eq!(decide(Kind::BuiltIn, &local()), None);
        assert_eq!(decide(Kind::Local, &local()), None);
    }

    #[test]
    fn remote_is_skipped() {
        let ssh = Context { ancestors: vec!["sudo".into(), "bash".into(), "sshd-session".into()], ..local() };
        assert_eq!(decide(Kind::Local, &ssh), Some("remote session"));
        let rhost = Context { rhost: "10.0.0.5".into(), ..local() };
        assert_eq!(decide(Kind::Local, &rhost), Some("remote host"));
        assert_eq!(decide(Kind::Local, &Context { rhost: "LOCALHOST ".into(), ..local() }), None);
        let session = Context { caller_session_remote: Some(true), ..local() };
        assert_eq!(decide(Kind::BuiltIn, &session), Some("remote session"));
    }

    #[test]
    fn unknowns_skip() {
        assert_eq!(decide(Kind::Local, &Context { caller_session_remote: None, ..local() }), Some("no login session"));
        assert_eq!(decide(Kind::Local, &Context { local_display: None, ..local() }), Some("no active local session"));
        assert_eq!(decide(Kind::Local, &Context { local_display: Some(false), ..local() }), Some("no active local session"));
        // The socket-activated polkit helper has no session of its own.
        let polkit =
            Context { service: "polkit-1".into(), caller_session_remote: None, ancestors: vec!["systemd".into()], ..local() };
        assert_eq!(decide(Kind::BuiltIn, &polkit), None);
    }

    #[test]
    fn the_login_screen_runs_methods() {
        let greeter = Context {
            service: "sddm".into(),
            ancestors: vec!["sddm-helper".into(), "sddm".into(), "systemd".into()],
            caller_session_remote: None,
            local_display: Some(false),
            ..Default::default()
        };
        assert_eq!(decide(Kind::BuiltIn, &greeter), None);
        assert_eq!(decide(Kind::Local, &greeter), None);
        assert_eq!(decide(Kind::BuiltIn, &Context { lid_closed: true, ..greeter.clone() }), Some("lid closed"));
        assert_eq!(decide(Kind::Local, &Context { rhost: "10.0.0.5".into(), ..greeter.clone() }), Some("remote host"));
        // Only SDDM's own helper counts, and only for the sddm service.
        let other = Context { ancestors: vec!["pam-try".into(), "bash".into(), "sddm".into()], ..greeter.clone() };
        assert_eq!(decide(Kind::BuiltIn, &other), Some("no login session"));
        let service = Context { service: "sudo".into(), ..greeter };
        assert_eq!(decide(Kind::BuiltIn, &service), Some("no login session"));
    }

    #[test]
    fn lid_only_affects_built_in_sensors() {
        let closed = Context { lid_closed: true, ..local() };
        assert_eq!(decide(Kind::BuiltIn, &closed), Some("lid closed"));
        assert_eq!(decide(Kind::Local, &closed), None);
    }

    #[test]
    fn reads_proc() {
        let root = tempfile::tempdir().unwrap();
        let p = root.path();
        let mk = |pid: u32, comm: &str, ppid: u32| {
            let d = p.join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(d.join("stat"), format!("{pid} ({comm} with) spaces) S {ppid} 1 1 0")).unwrap();
        };
        mk(300, "sudo", 200);
        mk(200, "bash", 100);
        mk(100, "sshd-session", 1);
        assert_eq!(ancestors(p, 300), vec!["sudo", "bash", "sshd-session"]);

        fs::create_dir_all(p.join("acpi/button/lid/LID0")).unwrap();
        fs::write(p.join("acpi/button/lid/LID0/state"), "state:      open\n").unwrap();
        assert!(!lid_closed(p));
        fs::write(p.join("acpi/button/lid/LID0/state"), "state:      closed\n").unwrap();
        assert!(lid_closed(p));

        fs::write(p.join("300/sessionid"), "4294967295").unwrap();
        assert_eq!(session_remote(p, &FakeRunner::new(), 300), None);
        fs::write(p.join("300/sessionid"), "7").unwrap();
        let r = FakeRunner::new().reply("/usr/bin/loginctl show-session 7 -p Remote --value", Output::ok("no\n"));
        assert_eq!(session_remote(p, &r, 300), Some(false));
    }

    #[test]
    fn display_session() {
        let r = FakeRunner::new().reply("/usr/bin/loginctl show-user ken -p Display --value", Output::ok("7\n")).reply(
            "/usr/bin/loginctl show-session 7 -p Remote -p Active -p Seat",
            Output::ok("Remote=no\nActive=yes\nSeat=seat0\n"),
        );
        assert_eq!(local_display(&r, "ken"), Some(true));
        let inactive = FakeRunner::new().reply("/usr/bin/loginctl show-user ken -p Display --value", Output::ok("7\n")).reply(
            "/usr/bin/loginctl show-session 7 -p Remote -p Active -p Seat",
            Output::ok("Remote=no\nActive=no\nSeat=seat0\n"),
        );
        assert_eq!(local_display(&inactive, "ken"), Some(false));
        assert_eq!(local_display(&FakeRunner::new(), "ken; rm"), None);
    }
}

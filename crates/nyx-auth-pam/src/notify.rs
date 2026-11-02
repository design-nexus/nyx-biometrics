//! `nyx-auth-notify`: tells the user's shell that a terminal sign-in is checking a face,
//! fingerprint or key, so it can show the scan. Run by `pam_exec` as root, it drops to the
//! user and calls the Omarchy shell's IPC with a fixed set of words. It never carries
//! anything secret and never affects the sign-in: it always exits 0, quickly.

pub const SHELL_CONFIG: &str = "/usr/share/omarchy/shell";
pub const RUNUSER: &str = "/usr/bin/runuser";
pub const QUICKSHELL: &str = "/usr/bin/quickshell";

/// The user's Wayland displays: `quickshell ipc` only finds a shell on the display it's told.
pub fn displays(runtime_dir: &std::path::Path) -> Vec<String> {
    use std::os::unix::fs::FileTypeExt;
    let mut out: Vec<String> = std::fs::read_dir(runtime_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_display(n))
        .collect();
    out.sort();
    out
}

fn is_display(name: &str) -> bool {
    name.strip_prefix("wayland-").is_some_and(|n| !n.is_empty() && n.len() <= 4 && n.chars().all(|c| c.is_ascii_digit()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Start,
    Failed,
    Done,
}

impl Event {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "start" => Some(Event::Start),
            "failed" => Some(Event::Failed),
            "done" => Some(Event::Done),
            _ => None,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Event::Start => "start",
            Event::Failed => "failed",
            Event::Done => "done",
        }
    }
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// The command that delivers one event, or `None` when anything looks off.
pub fn command(event: &str, method: &str, service: &str, user: &str, uid: u32, display: &str) -> Option<Vec<String>> {
    let event = Event::parse(event)?;
    if !matches!(method, "face" | "fingerprint" | "key" | "any")
        || !plain(service, 32)
        || !plain(user, 32)
        || uid == 0
        || !is_display(display)
    {
        return None;
    }
    Some(
        [
            RUNUSER,
            "-u",
            user,
            "--",
            "/usr/bin/env",
            "-i",
            &format!("XDG_RUNTIME_DIR=/run/user/{uid}"),
            &format!("WAYLAND_DISPLAY={display}"),
            "LANG=C.UTF-8",
            "PATH=/usr/bin",
            QUICKSHELL,
            "ipc",
            "-p",
            SHELL_CONFIG,
            "call",
            "nyx-auth",
            "notify",
            event.word(),
            service,
            method,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_fixed_command() {
        let c = command("start", "face", "sudo", "ken", 1000, "wayland-1").unwrap();
        assert_eq!(c[0], RUNUSER);
        assert_eq!(&c[1..3], ["-u", "ken"]);
        assert!(c.contains(&"XDG_RUNTIME_DIR=/run/user/1000".to_string()));
        assert!(c.contains(&"WAYLAND_DISPLAY=wayland-1".to_string()));
        assert_eq!(&c[c.len() - 5..], ["nyx-auth", "notify", "start", "sudo", "face"]);
    }

    #[test]
    fn refuses_anything_unexpected() {
        assert!(command("unlock", "face", "sudo", "ken", 1000, "wayland-1").is_none());
        assert!(command("start", "password", "sudo", "ken", 1000, "wayland-1").is_none());
        assert!(command("start", "face", "sudo; rm -rf /", "ken", 1000, "wayland-1").is_none());
        assert!(command("start", "face", "sudo", "ken --shell", 1000, "wayland-1").is_none());
        assert!(command("start", "face", "sudo", "root", 0, "wayland-1").is_none());
        assert!(command("start", "face", "sudo", "ken", 1000, "../wayland-1").is_none());
        assert!(command("start", "face", "sudo", "ken", 1000, "wayland-1.lock").is_none());
    }

    #[test]
    fn finds_display_sockets_only() {
        let dir = tempfile::tempdir().unwrap();
        let _sock = std::os::unix::net::UnixListener::bind(dir.path().join("wayland-1")).unwrap();
        std::fs::write(dir.path().join("wayland-1.lock"), "").unwrap();
        std::fs::write(dir.path().join("wayland-2"), "").unwrap();
        assert_eq!(displays(dir.path()), ["wayland-1"]);
        assert!(displays(&dir.path().join("missing")).is_empty());
    }
}

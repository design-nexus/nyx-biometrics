//! Gaze, for colour webcams. Gaze has no machine-readable output, so this reads only
//! exit codes and the daemon's presence on the system bus, and says "unknown" otherwise.

use std::time::Duration;

use super::{Backend, Daemon, Probe};
use crate::cmd::Runner;

pub const GAZE: &str = "/usr/bin/gaze";
const BUSCTL: &str = "/usr/bin/busctl";
pub const BUS_NAME: &str = "com.gundulabs.Gaze";
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn probe(runner: &dyn Runner) -> Probe {
    if !runner.exists(GAZE) {
        return Probe::missing(Backend::Gaze);
    }
    let mut probe = Probe { installed: true, rgb: Some(true), ..Probe::missing(Backend::Gaze) };
    probe.notes.clear();

    probe.daemon = match runner.run(BUSCTL, &["--system", "status", BUS_NAME], Duration::from_secs(3)) {
        Ok(o) if o.success() => Daemon::Running,
        Ok(_) => Daemon::Unreachable,
        Err(_) => Daemon::Unknown,
    };

    match runner.run(GAZE, &["list-faces"], TIMEOUT) {
        Ok(o) if o.success() => {
            let faces =
                o.stdout.lines().map(str::trim).filter(|l| !l.is_empty() && !l.ends_with(':') && !l.starts_with("No ")).count();
            probe.enrolled = Some(faces as u32);
        }
        Ok(o) => probe.notes.push(format!("gaze list-faces: {}", first_line(&o.stderr))),
        Err(e) => probe.notes.push(e.to_string()),
    }
    // Gaze's RGB liveness helps against prints and screens, but a webcam match stays
    // presence only in Nyx, so this is informational.
    probe.liveness = false;
    probe
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    #[test]
    fn running_with_a_face() {
        let r = FakeRunner::new()
            .reply("/usr/bin/busctl --system status com.gundulabs.Gaze", Output::ok("PID=123\n"))
            .reply("/usr/bin/gaze list-faces", Output::ok("Enrolled faces:\n  default\n"));
        let p = probe(&r);
        assert_eq!(p.daemon, Daemon::Running);
        assert_eq!(p.enrolled, Some(1));
        assert_eq!(p.rgb, Some(true));
        assert!(!p.liveness);
    }

    #[test]
    fn daemon_down_and_no_faces() {
        let r = FakeRunner::new()
            .reply("/usr/bin/busctl --system status com.gundulabs.Gaze", Output::failed(1, "No such unit"))
            .reply("/usr/bin/gaze list-faces", Output::ok("No faces enrolled.\n"));
        let p = probe(&r);
        assert_eq!(p.daemon, Daemon::Unreachable);
        assert_eq!(p.enrolled, Some(0));
        assert!(!probe(&FakeRunner::new()).installed);
    }
}

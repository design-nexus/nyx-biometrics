//! Irlume, through its versioned machine API (`irlume … --json --contract 1`).

use std::time::Duration;

use serde_json::Value;

use super::{Backend, Daemon, Probe};
use crate::cmd::Runner;

pub const IRLUME: &str = "/usr/bin/irlume";
pub const CONTRACT: &str = "1";
const TIMEOUT: Duration = Duration::from_secs(10);

/// Doctor checks that must pass before an infrared match counts as live. Irlume's IR gate
/// alone accepts a printed photo; its anti-spoofing models are what refuse one, so a
/// missing or failing model means presence only.
const LIVENESS_CHECKS: &[&str] = &["models", "stage-detection-model", "stage-recognition-model", "ir-calibration"];

pub fn probe(runner: &dyn Runner, user: &str) -> Probe {
    if !runner.exists(IRLUME) {
        return Probe::missing(Backend::Irlume);
    }
    let mut probe = Probe { installed: true, ..Probe::missing(Backend::Irlume) };
    probe.notes.clear();

    let status = match machine(runner, &["status", "--json", "--contract", CONTRACT, "--user", user]) {
        Ok(v) => v,
        Err(e) => {
            probe.notes.push(e);
            return probe;
        }
    };
    let data = &status["data"];
    probe.daemon = match data["daemon"].as_str() {
        Some("running") => Daemon::Running,
        Some("starting") => Daemon::Starting,
        Some("unreachable") => Daemon::Unreachable,
        Some("access-denied") => Daemon::AccessDenied,
        _ => Daemon::Unknown,
    };
    if data["enrollment"]["known"].as_bool() == Some(true) {
        probe.enrolled = data["enrollment"]["profiles"].as_u64().map(|n| n as u32);
    }
    if data["camera"]["known"].as_bool() == Some(true) {
        probe.ir = data["camera"]["ir"].as_bool();
        probe.rgb = data["camera"]["rgb"].as_bool();
    }
    if data["face_disabled"].as_bool() == Some(true) {
        probe.enrolled = Some(0);
        probe.notes.push("Face sign-in is turned off in Irlume".into());
    }
    if data["templates"].as_str() == Some("plaintext") {
        probe.notes.push("Face templates aren't encrypted (no TPM)".into());
    }

    match machine(runner, &["doctor", "--json", "--contract", CONTRACT, "--user", user]) {
        Ok(doc) => {
            let checks = doc["data"]["checks"].as_array().cloned().unwrap_or_default();
            let state = |id: &str| checks.iter().find(|c| c["id"] == id).and_then(|c| c["state"].as_str()).unwrap_or("missing");
            probe.liveness = LIVENESS_CHECKS.iter().all(|id| state(id) == "pass");
            if !probe.liveness {
                let failing: Vec<&str> = LIVENESS_CHECKS.iter().copied().filter(|id| state(id) != "pass").collect();
                probe.notes.push(format!("Anti-spoofing not confirmed ({})", failing.join(", ")));
            }
            if state("debug-tracing") == "warn" {
                probe.notes.push("Irlume debug tracing is on and logs match scores".into());
            }
            if state("login-wiring") == "pass" {
                probe.notes.push("Irlume has wired PAM itself; Nyx will take over that wiring".into());
            }
        }
        Err(e) => probe.notes.push(e),
    }
    probe
}

/// Runs a machine command and returns its document, or why it failed. A document with
/// `ok: false` is reported by its error code.
fn machine(runner: &dyn Runner, args: &[&str]) -> Result<Value, String> {
    let out = runner.run(IRLUME, args, TIMEOUT).map_err(|e| e.to_string())?;
    let doc: Value = serde_json::from_str(out.stdout.trim()).map_err(|_| format!("irlume {} gave no JSON", args[0]))?;
    if doc["contract_version"].as_u64() != Some(1) {
        return Err("irlume doesn't speak machine contract 1".into());
    }
    if doc["ok"].as_bool() != Some(true) {
        let code = doc["error"]["code"].as_str().unwrap_or("unknown");
        return Err(format!("irlume {}: {code}", args[0]));
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    const STATUS: &str = "/usr/bin/irlume status --json --contract 1 --user ken";
    const DOCTOR: &str = "/usr/bin/irlume doctor --json --contract 1 --user ken";

    fn status(daemon: &str, profiles: u32, ir: bool) -> String {
        format!(
            r#"{{"contract_version":1,"engine_version":"0.15.0","command":"status","ok":true,"data":{{"daemon":"{daemon}","auth_method":"auto","face_disabled":false,"enrollment":{{"known":true,"profiles":{profiles},"scans":10}},"templates":"encrypted","camera":{{"known":true,"rgb":true,"ir":{ir}}},"fingerprint":false}}}}"#
        )
    }

    fn doctor(states: &[(&str, &str)]) -> String {
        let checks: Vec<String> = states.iter().map(|(id, s)| format!(r#"{{"id":"{id}","state":"{s}"}}"#)).collect();
        format!(
            r#"{{"contract_version":1,"engine_version":"0.15.0","command":"doctor","ok":true,"data":{{"checks":[{}]}}}}"#,
            checks.join(",")
        )
    }

    const ALL_PASS: &[(&str, &str)] = &[
        ("models", "pass"),
        ("stage-detection-model", "pass"),
        ("stage-recognition-model", "pass"),
        ("ir-calibration", "pass"),
        ("tpm", "pass"),
    ];

    #[test]
    fn ready_with_liveness() {
        let r =
            FakeRunner::new().reply(STATUS, Output::ok(&status("running", 1, true))).reply(DOCTOR, Output::ok(&doctor(ALL_PASS)));
        let p = probe(&r, "ken");
        assert!(p.installed);
        assert_eq!(p.daemon, Daemon::Running);
        assert_eq!(p.enrolled, Some(1));
        assert_eq!(p.ir, Some(true));
        assert!(p.liveness, "{:?}", p.notes);
    }

    #[test]
    fn a_failing_model_check_means_no_liveness() {
        let mut states = ALL_PASS.to_vec();
        states[3] = ("ir-calibration", "warn");
        let r =
            FakeRunner::new().reply(STATUS, Output::ok(&status("running", 1, true))).reply(DOCTOR, Output::ok(&doctor(&states)));
        let p = probe(&r, "ken");
        assert!(!p.liveness);
        assert!(p.notes.iter().any(|n| n.contains("ir-calibration")));

        // A doctor that can't run is unknown, which counts as no.
        let r = FakeRunner::new().reply(STATUS, Output::ok(&status("running", 1, true)));
        assert!(!probe(&r, "ken").liveness);
    }

    #[test]
    fn unknown_enrollment_is_not_zero() {
        let doc = r#"{"contract_version":1,"engine_version":"0.15.0","command":"status","ok":true,"data":{"daemon":"unreachable","enrollment":{"known":false},"camera":{"known":false,"rgb":true,"ir":true}}}"#;
        let r = FakeRunner::new().reply(STATUS, Output::ok(doc)).reply(DOCTOR, Output::ok(&doctor(ALL_PASS)));
        let p = probe(&r, "ken");
        assert_eq!(p.daemon, Daemon::Unreachable);
        assert_eq!(p.enrolled, None);
        assert_eq!(p.ir, None);
    }

    #[test]
    fn refusals_and_missing() {
        assert!(!probe(&FakeRunner::new(), "ken").installed);
        let refused = r#"{"contract_version":1,"engine_version":"0.15.0","command":"status","ok":false,"error":{"code":"daemon-unavailable","retryable":true}}"#;
        let p = probe(
            &FakeRunner::new()
                .reply(STATUS, Output::failed(1, ""))
                .reply(STATUS, Output { status: Some(1), stdout: refused.into(), stderr: String::new() }),
            "ken",
        );
        assert!(p.installed);
        assert_eq!(p.daemon, Daemon::Unknown);
        assert!(p.notes[0].contains("daemon-unavailable"));
        let newer = r#"{"contract_version":2,"ok":true,"data":{}}"#;
        let p = probe(&FakeRunner::new().reply(STATUS, Output::ok(newer)), "ken");
        assert!(p.notes[0].contains("contract 1"));
    }

    #[test]
    fn disabled_face_counts_as_not_enrolled() {
        let doc = status("running", 2, true).replace(r#""face_disabled":false"#, r#""face_disabled":true"#);
        let r = FakeRunner::new().reply(STATUS, Output::ok(&doc)).reply(DOCTOR, Output::ok(&doctor(ALL_PASS)));
        assert_eq!(probe(&r, "ken").enrolled, Some(0));
    }
}

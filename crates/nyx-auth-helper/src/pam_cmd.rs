//! The helper's PAM verbs: probing, applying, arming the rollback timer, confirming.

use std::process::Command;

use nyx_auth_helper::INSTALL_PATH;
use nyx_auth_helper::pam::{self, ROLLBACK_SECS, Root};
use nyx_auth_hw::SystemRunner;
use nyx_auth_hw::report::{Paths, Report};
use nyx_auth_pam::Modules;

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";

fn unit(id: &str) -> String {
    format!("nyx-auth-rollback-{id}")
}

fn now_id() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}-{}", std::process::id())
}

fn quiet(cmd: &mut Command) -> bool {
    cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

fn daemon_reload() {
    quiet(Command::new(SYSTEMCTL).arg("daemon-reload"));
}

pub fn apply(user: &str, surface: &str, expected: &str, migrate: bool, policy: &str) -> Result<String, String> {
    let surface = pam::surface_key(surface).ok_or("unknown surface")?;
    let report = Report::collect(&SystemRunner, &Paths::system(), user);
    let face = report.face.as_ref().map(|c| c.backend);
    let modules = Modules { migrate_omarchy: migrate, ..Modules::system(face) };
    let root = Root::system();
    let changes = pam::prepare(&root, policy, surface, &report.inventory(), &modules).map_err(|e| e.to_string())?;
    if pam::fingerprint(&changes) != expected {
        return Err(pam::PamError::Changed.to_string());
    }
    let effective = pam::effective(&root, &changes);
    if effective.is_empty() {
        return Ok("nothing to change".into());
    }
    let id = now_id();
    let manifest = pam::apply(&root, &effective, surface, &id).map_err(|e| e.to_string())?;
    if pam::touches_dropin(&effective) {
        daemon_reload();
    }
    let armed = quiet(
        Command::new(SYSTEMD_RUN)
            .arg(format!("--unit={}", unit(&id)))
            .arg(format!("--on-active={ROLLBACK_SECS}"))
            .arg("--timer-property=AccuracySec=1s")
            .arg("--description=Undo an unconfirmed Nyx Biometrics sign-in change")
            .args([INSTALL_PATH, "pam-rollback", &id]),
    );
    if !armed {
        // Never leave a change in place without its safety net.
        pam::restore(&root, &id).map_err(|e| e.to_string())?;
        if pam::touches_dropin(&effective) {
            daemon_reload();
        }
        return Err("couldn't arm the automatic undo, so the change was taken back".into());
    }
    Ok(manifest.id)
}

pub fn confirm(id: &str) -> Result<String, String> {
    let root = Root::system();
    let m = pam::load(&root, id).map_err(|e| e.to_string())?;
    if m.restored {
        return Err("that change was already undone".into());
    }
    quiet(Command::new(SYSTEMCTL).args(["stop", &format!("{}.timer", unit(id))]));
    pam::confirm(&root, id).map_err(|e| e.to_string())?;
    Ok(String::new())
}

pub fn restore(id: Option<&str>) -> Result<String, String> {
    let root = Root::system();
    let m = match id {
        Some(id) => pam::load(&root, id),
        None => pam::latest(&root),
    }
    .map_err(|e| e.to_string())?;
    quiet(Command::new(SYSTEMCTL).args(["stop", &format!("{}.timer", unit(&m.id))]));
    pam::restore(&root, &m.id).map_err(|e| e.to_string())?;
    if m.entries.iter().any(|e| e.path == nyx_auth_pam::generate::POLKIT_DROPIN) {
        daemon_reload();
    }
    Ok(m.id)
}

/// Run by the timer: undo unless confirmed in time.
pub fn rollback(id: &str) -> Result<String, String> {
    let root = Root::system();
    let m = pam::load(&root, id).map_err(|e| e.to_string())?;
    if m.confirmed || m.restored {
        return Ok(String::new());
    }
    pam::restore(&root, id).map_err(|e| e.to_string())?;
    if m.entries.iter().any(|e| e.path == nyx_auth_pam::generate::POLKIT_DROPIN) {
        daemon_reload();
    }
    Ok(id.into())
}

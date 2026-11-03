//! `nyx-authctl status --json` and `policy set`: what Nyx Settings shows and changes.

use std::process::ExitCode;

use nyx_auth_core::{Assurance, Camera, MethodKind, PolicySet, Surface};
use nyx_auth_helper::pam::{self, Root};
use nyx_auth_hw::face::Backend;
use nyx_auth_hw::fprint::Fprint;
use nyx_auth_hw::report::Report;
use nyx_auth_hw::u2f::{self, AuthFile, Names, Role};
use nyx_auth_pam::Modules;
use serde_json::{Value, json};

fn kind_key(k: MethodKind) -> &'static str {
    match k {
        MethodKind::Password => "password",
        MethodKind::Fingerprint => "fingerprint",
        MethodKind::Face => "face",
        MethodKind::SecurityKey => "security-key",
    }
}

fn kind_from(s: &str) -> Option<MethodKind> {
    MethodKind::ALL.into_iter().find(|k| kind_key(*k) == s)
}

fn surface_from(s: &str) -> Option<Surface> {
    Surface::ALL.into_iter().find(|x| x.key() == s)
}

/// Whether what's on disk already matches the policy for a PAM surface.
fn in_effect(report: &Report, policy: &str, surface: Surface) -> Value {
    if !surface.is_system() {
        return json!("not-needed");
    }
    let modules = Modules::system(report.face.as_ref().map(|c| c.backend));
    match pam::prepare(&Root::system(), policy, surface, &report.inventory(), &modules) {
        Ok(changes) if pam::effective(&Root::system(), &changes).is_empty() => json!("yes"),
        Ok(_) => json!("no"),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

fn autologin() -> bool {
    let mut text = std::fs::read_to_string("/etc/sddm.conf").unwrap_or_default();
    if let Ok(dir) = std::fs::read_dir("/etc/sddm.conf.d") {
        for e in dir.flatten() {
            text.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
        }
    }
    let mut in_section = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = line == "[Autologin]";
        } else if in_section && line.strip_prefix("User=").is_some_and(|u| !u.trim().is_empty()) {
            return true;
        }
    }
    false
}

pub fn status() -> ExitCode {
    let user = crate::user();
    let report = crate::report();
    let inv = report.inventory();
    let policy_text = std::fs::read_to_string(crate::policy_path()).unwrap_or_else(|_| PolicySet::default().to_toml());
    let policy = PolicySet::from_toml(&policy_text).unwrap_or_default();

    let face = report.face.as_ref().map(|c| {
        let probe = if c.backend == Backend::Irlume { &report.irlume } else { &report.gaze };
        let level = match inv.face {
            Some(f) if f.camera == Camera::Infrared && f.liveness => "one-factor",
            Some(_) => "presence",
            None => "none",
        };
        json!({
            "backend": c.backend.label(),
            "camera": if c.camera == Camera::Infrared { "infrared" } else { "colour" },
            "installed": probe.installed,
            "enrolled": probe.enrolled,
            "ready": inv.face.is_some(),
            "level": level,
            "reason": c.reason,
        })
    });

    let fingerprint = match &report.fingerprint {
        Fprint::Ready { readers } => json!({
            "state": "ready",
            "readers": readers.iter().map(|r| json!({ "name": r.name, "fingers": r.enrolled })).collect::<Vec<_>>(),
        }),
        Fprint::NotInstalled if !report.usb_readers.is_empty() => json!({ "state": "not-installed" }),
        Fprint::Error { message } => json!({ "state": "error", "message": message }),
        _ => json!({ "state": "no-reader" }),
    };

    let file = std::fs::read_to_string(u2f::AUTHFILE).ok().and_then(|t| AuthFile::parse(&t).ok()).unwrap_or_default();
    let names = std::fs::read_to_string(std::path::Path::new(u2f::NAMES_DIR).join(format!("{user}.toml")))
        .ok()
        .and_then(|t| Names::parse(&t).ok())
        .unwrap_or_default();
    let keys: Vec<Value> = file
        .credentials(&user)
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let meta = names.name_of(c);
            json!({
                "id": c.id(),
                "name": meta.map(|n| n.name.clone()).unwrap_or_else(|| format!("Security key {}", i + 1)),
                "role": if meta.map(|n| n.role) == Some(Role::Backup) { "backup" } else { "primary" },
                "pin": c.verification(),
            })
        })
        .collect();

    let surfaces: Vec<Value> = Surface::ALL
        .iter()
        .map(|s| {
            let p = policy.get(*s);
            let check = match p.plan(*s, &inv) {
                Ok(plan) => {
                    json!({ "ok": true, "unavailable": plan.unavailable.iter().map(|k| kind_key(*k)).collect::<Vec<_>>() })
                }
                Err(errs) => json!({ "ok": false, "errors": errs.iter().map(|e| e.to_string()).collect::<Vec<_>>() }),
            };
            json!({
                "key": s.key(),
                "label": s.label(),
                "system": s.is_system(),
                "methods": p.methods.iter().map(|k| kind_key(*k)).collect::<Vec<_>>(),
                "require_all": p.require_all.iter().map(|k| kind_key(*k)).collect::<Vec<_>>(),
                "minimum": p.minimum.label(),
                "check": check,
                "in_effect": in_effect(&report, &policy_text, *s),
            })
        })
        .collect();

    let helper = std::process::Command::new(nyx_auth_helper::INSTALL_PATH)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| v.trim().parse::<u32>().ok());
    let doc = json!({
        "helper": match helper {
            Some(v) if v == nyx_auth_helper::HELPER_VERSION => "ready",
            Some(_) => "outdated",
            None => "missing",
        },
        "face": face,
        "fingerprint": fingerprint,
        "keys": keys,
        "ssh_keys": crate::ssh::keys(&std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".ssh"))
            .iter()
            .map(|k| json!({ "file": k.file, "kind": k.kind, "comment": k.comment }))
            .collect::<Vec<_>>(),
        "keys_plugged": report.keys_plugged,
        "surfaces": surfaces,
        "findings": report.findings(),
        "autologin": autologin(),
        "tpm": report.tpm,
    });
    println!("{}", serde_json::to_string_pretty(&doc).expect("status serializes"));
    ExitCode::SUCCESS
}

/// Turn one method on or off for one surface, refusing anything the policy engine refuses.
pub fn policy_set(surface: &str, method: &str, on: &str) -> ExitCode {
    let (Some(surface), Some(kind), Some(on)) = (
        surface_from(surface),
        kind_from(method),
        match on {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        },
    ) else {
        eprintln!("Usage: nyx-authctl policy set SURFACE METHOD on|off");
        return ExitCode::from(2);
    };
    let path = crate::policy_path();
    let mut set = match std::fs::read_to_string(&path) {
        Ok(t) => match PolicySet::from_toml(&t) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
        Err(_) => PolicySet::default(),
    };
    let p = set.get_mut(surface);
    p.methods.retain(|k| *k != kind);
    if on {
        // Keep the standard order: face, fingerprint, key, then the password.
        let rank = |k: &MethodKind| MethodKind::ALL.iter().position(|x| x == k).unwrap_or(9);
        p.methods.push(kind);
        p.methods.sort_by_key(rank);
        // A presence-only face (webcam) is fine for the lock screen only.
        if surface == Surface::LockScreen && kind == MethodKind::Face {
            p.minimum = p.minimum.min(Assurance::Presence);
        }
    }
    let inv = crate::report().inventory();
    if let Err(errs) = set.get(surface).plan(surface, &inv) {
        for e in errs {
            eprintln!("{e}");
        }
        return ExitCode::FAILURE;
    }
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let tmp = path.with_extension("toml.new");
    if let Err(e) = std::fs::write(&tmp, set.to_toml()).and_then(|_| std::fs::rename(&tmp, &path)) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

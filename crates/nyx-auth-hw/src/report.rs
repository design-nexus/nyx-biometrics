//! Everything the probes found, as an inventory for the policy engine and as plain-language
//! findings for `nyx-authctl doctor` and Settings.

use std::fs;
use std::path::PathBuf;

use nyx_auth_core::{Inventory, KeyInfo};
use serde::Serialize;

use crate::camera::{self, CameraNode};
use crate::cmd::Runner;
use crate::face::{self, Backend, Choice, Probe};
use crate::fido2::{self, Keys};
use crate::fprint::{self, Fprint, Support, UsbReader};
use crate::tpm;
use crate::u2f::{self, AuthFile, Names};

/// Where to look. Tests point these at a temporary tree.
#[derive(Debug, Clone)]
pub struct Paths {
    pub sys: PathBuf,
    pub dev: PathBuf,
    pub pam_modules: PathBuf,
    pub authfile: PathBuf,
    pub names_dir: PathBuf,
    pub omarchy_authfile: PathBuf,
    pub libfprint_hwdb: PathBuf,
}

impl Paths {
    pub fn system() -> Self {
        Self {
            sys: "/sys".into(),
            dev: "/dev".into(),
            pam_modules: "/usr/lib/security".into(),
            authfile: u2f::AUTHFILE.into(),
            names_dir: u2f::NAMES_DIR.into(),
            omarchy_authfile: u2f::OMARCHY_AUTHFILE.into(),
            libfprint_hwdb: fprint::LIBFPRINT_HWDB.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Missing,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub area: &'static str,
    pub status: Status,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub user: String,
    pub cameras: Vec<CameraNode>,
    pub irlume: Probe,
    pub gaze: Probe,
    pub face: Option<Choice>,
    pub fingerprint: Fprint,
    pub usb_readers: Vec<UsbReader>,
    pub keys_plugged: Keys,
    pub keys_registered: Vec<KeyInfo>,
    /// Registrations Omarchy's FIDO2 setup made, which Nyx can move into its own file.
    pub omarchy_keys: usize,
    pub tpm: bool,
    pub pam_modules: Vec<(String, bool)>,
}

const MODULES: &[&str] = &["pam_fprintd.so", "pam_u2f.so", "pam_irlume.so", "pam_gaze.so"];

impl Report {
    pub fn collect(runner: &dyn Runner, paths: &Paths, user: &str) -> Self {
        let cameras = camera::discover_with(&paths.sys, &paths.dev, camera::formats);
        Self::collect_with(runner, paths, user, cameras)
    }

    pub fn collect_with(runner: &dyn Runner, paths: &Paths, user: &str, cameras: Vec<CameraNode>) -> Self {
        let irlume = Backend::Irlume.probe(runner, user);
        let gaze = Backend::Gaze.probe(runner, user);
        let choice = face::choose(&cameras, &irlume, &gaze);
        let hwdb = fs::read_to_string(&paths.libfprint_hwdb).ok();
        let authfile = fs::read_to_string(&paths.authfile).ok().and_then(|t| AuthFile::parse(&t).ok()).unwrap_or_default();
        let names = fs::read_to_string(paths.names_dir.join(format!("{user}.toml")))
            .ok()
            .and_then(|t| Names::parse(&t).ok())
            .unwrap_or_default();
        let omarchy_keys = fs::read_to_string(&paths.omarchy_authfile)
            .ok()
            .and_then(|t| AuthFile::parse(&t).ok())
            .map(|f| f.credentials(user).len())
            .unwrap_or(0);
        Self {
            user: user.into(),
            cameras,
            irlume,
            gaze,
            face: choice,
            fingerprint: fprint::probe(runner, user),
            usb_readers: fprint::usb_readers(&paths.sys, hwdb.as_deref()),
            keys_plugged: fido2::probe(runner),
            keys_registered: u2f::key_infos(&authfile, &names, user),
            omarchy_keys,
            tpm: tpm::present(&paths.dev),
            pam_modules: MODULES.iter().map(|m| (m.to_string(), paths.pam_modules.join(m).is_file())).collect(),
        }
    }

    fn module(&self, name: &str) -> bool {
        self.pam_modules.iter().any(|(m, ok)| m == name && *ok)
    }

    /// What the policy engine may use: only enrolled methods whose PAM module is installed.
    pub fn inventory(&self) -> Inventory {
        let face = self.face.as_ref().and_then(|c| {
            let probe = match c.backend {
                Backend::Irlume => &self.irlume,
                Backend::Gaze => &self.gaze,
            };
            face::capability(c, probe).filter(|_| self.module(c.backend.pam_module()))
        });
        Inventory {
            password: true,
            fingerprint: self.fingerprint.enrolled() && self.module("pam_fprintd.so"),
            face,
            keys: if self.module("pam_u2f.so") { self.keys_registered.clone() } else { Vec::new() },
        }
    }

    pub fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut add = |area, status, message: String| out.push(Finding { area, status, message });

        // Cameras and face.
        if self.cameras.is_empty() {
            add("face", Status::Missing, "No camera found".into());
        }
        for c in &self.cameras {
            let kind = match c.kind {
                nyx_auth_core::Camera::Infrared => "Infrared camera",
                nyx_auth_core::Camera::Rgb => "Colour camera",
            };
            let id = c.usb_id.as_deref().map(|id| format!(" ({id})")).unwrap_or_default();
            add("face", Status::Info, format!("{kind} at {}{id}", c.device.display()));
        }
        if let Some(choice) = &self.face {
            let probe = if choice.backend == Backend::Irlume { &self.irlume } else { &self.gaze };
            let name = choice.backend.label();
            let (status, message) = if choice.ready && self.module(choice.backend.pam_module()) {
                let level = match face::capability(choice, probe) {
                    Some(cap) if cap.liveness => "counts as one factor",
                    _ => "shows presence only, so it can unlock the lock screen but not more",
                };
                (Status::Ok, format!("Face sign-in with {name} is ready and {level}"))
            } else if !probe.installed {
                (Status::Missing, format!("{}. Install {name} to use it", choice.reason))
            } else if probe.enrolled == Some(0) {
                (Status::Warn, format!("{name} is installed but no face is enrolled"))
            } else if !self.module(choice.backend.pam_module()) {
                (Status::Warn, format!("{name}'s PAM module ({}) isn't installed", choice.backend.pam_module()))
            } else {
                (Status::Warn, format!("{name} isn't ready (daemon: {:?})", probe.daemon))
            };
            add("face", status, message);
            for note in &probe.notes {
                add("face", Status::Info, note.clone());
            }
        }

        // Fingerprint.
        match &self.fingerprint {
            Fprint::Ready { readers } => {
                for r in readers {
                    if r.enrolled.is_empty() {
                        add("fingerprint", Status::Warn, format!("{} has no fingerprints enrolled", r.name));
                    } else {
                        add("fingerprint", Status::Ok, format!("{} with {} finger(s) enrolled", r.name, r.enrolled.len()));
                    }
                }
                if !self.module("pam_fprintd.so") {
                    add("fingerprint", Status::Warn, "pam_fprintd.so isn't installed".into());
                }
            }
            Fprint::NoReader if self.usb_readers.is_empty() => {
                add("fingerprint", Status::Missing, "No fingerprint reader found".into())
            }
            Fprint::NotInstalled if self.usb_readers.is_empty() => {
                add("fingerprint", Status::Missing, "No fingerprint reader found".into())
            }
            Fprint::Error { message } => add("fingerprint", Status::Error, format!("fprintd: {message}")),
            _ => {}
        }
        for r in &self.usb_readers {
            let (status, what) = match r.support {
                Support::Supported => (Status::Info, "is supported by libfprint"),
                Support::KnownUnsupported => (Status::Warn, "is a known reader that libfprint doesn't support"),
                Support::Unconfirmed => (Status::Info, "looks like a fingerprint reader; install libfprint to confirm support"),
            };
            add("fingerprint", status, format!("USB device {} “{}” {what}", r.usb_id, r.product));
        }
        if matches!(self.fingerprint, Fprint::NotInstalled)
            && self.usb_readers.iter().any(|r| r.support != Support::KnownUnsupported)
        {
            add("fingerprint", Status::Missing, "fprintd isn't installed".into());
        }

        // Security keys.
        match &self.keys_plugged {
            Keys::NotInstalled => add("security-key", Status::Missing, "libfido2's tools aren't installed".into()),
            Keys::Error { message } => add("security-key", Status::Error, message.clone()),
            Keys::Present { keys } => {
                for (token, info) in keys {
                    let detail = match info {
                        Some(i) if !i.fido2() => "U2F only, no PIN support".to_string(),
                        Some(i) => format!(
                            "PIN {}{}{}",
                            if i.pin_set() {
                                "set"
                            } else if i.can_verify() {
                                "not set"
                            } else {
                                "not supported"
                            },
                            if i.has_sensor() { ", has a fingerprint sensor" } else { "" },
                            if i.hmac_secret() { ", can unlock Passwords" } else { "" },
                        ),
                        None => "couldn't read its details; it may have been unplugged".into(),
                    };
                    add("security-key", Status::Info, format!("{} plugged in at {}: {detail}", token.label, token.device));
                }
            }
        }
        match self.keys_registered.len() {
            0 => add("security-key", Status::Info, "No security keys registered".into()),
            1 => add(
                "security-key",
                Status::Warn,
                "One security key registered. Register a backup so losing it doesn't lock you out".into(),
            ),
            n => add("security-key", Status::Ok, format!("{n} security keys registered")),
        }
        if !self.keys_registered.is_empty() && !self.module("pam_u2f.so") {
            add("security-key", Status::Warn, "pam_u2f.so isn't installed".into());
        }
        if self.omarchy_keys > 0 {
            add(
                "security-key",
                Status::Info,
                format!(
                    "Omarchy's FIDO2 setup registered {} key(s) in {}; Nyx can move them",
                    self.omarchy_keys,
                    u2f::OMARCHY_AUTHFILE
                ),
            );
        }

        add(
            "tpm",
            if self.tpm { Status::Ok } else { Status::Warn },
            if self.tpm {
                "TPM 2.0 available".into()
            } else {
                "No TPM: face templates and Vault quick-unlock keys can't be sealed".into()
            },
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};
    use nyx_auth_core::{Camera, FaceCapability};

    fn paths(root: &std::path::Path) -> Paths {
        Paths {
            sys: root.join("sys"),
            dev: root.join("dev"),
            pam_modules: root.join("security"),
            authfile: root.join("u2f_keys"),
            names_dir: root.join("keys"),
            omarchy_authfile: root.join("fido2"),
            libfprint_hwdb: root.join("hwdb"),
        }
    }

    fn node(device: &str, kind: Camera) -> CameraNode {
        CameraNode { device: device.into(), name: "cam".into(), usb_id: Some("3277:0060".into()), formats: vec![], kind }
    }

    /// The G16 today: cameras, a TPM, nothing installed or enrolled.
    #[test]
    fn g16_before_setup() {
        let root = tempfile::tempdir().unwrap();
        let p = paths(root.path());
        fs::create_dir_all(&p.dev).unwrap();
        fs::write(p.dev.join("tpmrm0"), "").unwrap();
        let runner = FakeRunner::new()
            .reply("/usr/bin/fido2-token -L", Output::ok(""))
            .reply(
                "/usr/bin/busctl --system --json=short call net.reactivated.Fprint /net/reactivated/Fprint/Manager net.reactivated.Fprint.Manager GetDevices",
                Output::failed(1, "The name net.reactivated.Fprint was not provided by any .service files"),
            );
        let report = Report::collect_with(
            &runner,
            &p,
            "ken",
            vec![node("/dev/video0", Camera::Rgb), node("/dev/video2", Camera::Infrared)],
        );

        assert_eq!(report.inventory(), Inventory { password: true, ..Default::default() });
        let f = report.findings();
        let has = |area: &str, status: Status, text: &str| {
            f.iter().any(|x| x.area == area && x.status == status && x.message.contains(text))
        };
        assert!(has("face", Status::Missing, "Install Irlume"), "{f:#?}");
        assert!(has("fingerprint", Status::Missing, "No fingerprint reader"), "{f:#?}");
        assert!(has("security-key", Status::Info, "No security keys registered"), "{f:#?}");
        assert!(has("tpm", Status::Ok, "TPM 2.0"), "{f:#?}");
    }

    #[test]
    fn methods_need_their_pam_module() {
        let root = tempfile::tempdir().unwrap();
        let p = paths(root.path());
        fs::write(
            &p.authfile,
            "ken:kh1AAAAAAAAAAAAAAAAAAAA,pk1,es256,+presence:kh2BBBBBBBBBBBBBBBBBBBB,pk2,es256,+presence+pin\n",
        )
        .unwrap();
        let runner = FakeRunner::new();
        let report = Report::collect_with(&runner, &p, "ken", vec![]);
        assert!(report.inventory().keys.is_empty(), "no pam_u2f.so yet");

        fs::create_dir_all(&p.pam_modules).unwrap();
        fs::write(p.pam_modules.join("pam_u2f.so"), "").unwrap();
        let report = Report::collect_with(&runner, &p, "ken", vec![]);
        let keys = report.inventory().keys;
        assert_eq!(keys.len(), 2);
        assert!(keys[1].verification);
        assert!(report.findings().iter().any(|f| f.status == Status::Ok && f.message == "2 security keys registered"));
    }

    #[test]
    fn rgb_face_via_gaze_is_presence_only() {
        let root = tempfile::tempdir().unwrap();
        let p = paths(root.path());
        fs::create_dir_all(&p.pam_modules).unwrap();
        fs::write(p.pam_modules.join("pam_gaze.so"), "").unwrap();
        let runner = FakeRunner::new()
            .reply("/usr/bin/busctl --system status com.gundulabs.Gaze", Output::ok(""))
            .reply("/usr/bin/gaze list-faces", Output::ok("default\n"));
        let report = Report::collect_with(&runner, &p, "ken", vec![node("/dev/video0", Camera::Rgb)]);
        assert_eq!(report.inventory().face, Some(FaceCapability { camera: Camera::Rgb, liveness: false }));
        assert!(report.findings().iter().any(|f| f.message.contains("presence only")));
    }
}

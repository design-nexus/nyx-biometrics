//! Face recognition backends. Nyx never matches faces itself.
//!
//! Irlume handles infrared cameras; Gaze handles colour webcams. Exactly one backend is
//! wired into PAM per camera, so two daemons never fight over a sensor or prompt twice.

pub mod gaze;
pub mod irlume;

use nyx_auth_core::{Camera, FaceCapability};
use serde::{Deserialize, Serialize};

use crate::camera::CameraNode;
use crate::cmd::Runner;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Irlume,
    Gaze,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::Irlume => "Irlume",
            Backend::Gaze => "Gaze",
        }
    }

    pub fn pam_module(self) -> &'static str {
        match self {
            Backend::Irlume => "pam_irlume.so",
            Backend::Gaze => "pam_gaze.so",
        }
    }

    /// The command that enrolls the current user, run in a terminal so its own guidance
    /// shows. Nyx doesn't reimplement enrollment.
    pub fn enroll_command(self) -> &'static [&'static str] {
        match self {
            Backend::Irlume => &["/usr/bin/irlume", "enroll"],
            Backend::Gaze => &["/usr/bin/gaze", "add-face", "default"],
        }
    }

    pub fn probe(self, runner: &dyn Runner, user: &str) -> Probe {
        match self {
            Backend::Irlume => irlume::probe(runner, user),
            Backend::Gaze => gaze::probe(runner),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Daemon {
    Running,
    Starting,
    Unreachable,
    AccessDenied,
    Unknown,
}

/// What a backend reports. `None` means it couldn't find out, which is never read as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub backend: Backend,
    pub installed: bool,
    pub daemon: Daemon,
    pub enrolled: Option<u32>,
    pub ir: Option<bool>,
    pub rgb: Option<bool>,
    /// The backend's anti-spoofing checks are present and passing. Unknown counts as no.
    pub liveness: bool,
    /// Short facts for diagnostics, never scores, frames or embeddings.
    pub notes: Vec<String>,
}

impl Probe {
    pub fn missing(backend: Backend) -> Self {
        Self {
            backend,
            installed: false,
            daemon: Daemon::Unknown,
            enrolled: None,
            ir: None,
            rgb: None,
            liveness: false,
            notes: vec![format!("{} isn't installed", backend.label())],
        }
    }

    fn usable(&self) -> bool {
        self.installed && matches!(self.daemon, Daemon::Running | Daemon::Starting) && self.enrolled.is_some_and(|n| n > 0)
    }
}

/// Which backend owns which camera, chosen from what's plugged in and installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Choice {
    pub backend: Backend,
    pub camera: Camera,
    /// The backend is installed, running and has a face enrolled.
    pub ready: bool,
    pub reason: String,
}

/// Irlume for an infrared camera; Gaze for a colour one when there's no usable infrared path.
pub fn choose(cameras: &[CameraNode], irlume: &Probe, gaze: &Probe) -> Option<Choice> {
    let has_ir = cameras.iter().any(|c| c.kind == Camera::Infrared);
    let has_rgb = cameras.iter().any(|c| c.kind == Camera::Rgb);
    let irlume_drives_ir = irlume.installed && irlume.ir != Some(false);

    if has_ir && (irlume_drives_ir || !irlume.installed) {
        return Some(Choice {
            backend: Backend::Irlume,
            camera: Camera::Infrared,
            ready: irlume.usable() && irlume.ir == Some(true),
            reason: "This computer has an infrared camera, which Irlume uses".into(),
        });
    }
    if has_rgb {
        let reason = if has_ir {
            "Irlume can't use the infrared camera, so Gaze uses the colour camera"
        } else {
            "This computer only has a colour camera, which Gaze uses"
        };
        return Some(Choice { backend: Backend::Gaze, camera: Camera::Rgb, ready: gaze.usable(), reason: reason.into() });
    }
    None
}

/// The face method the policy engine sees, or `None` until a face is enrolled.
///
/// An RGB match is always presence only; an infrared match needs the backend's liveness
/// checks to count as a factor.
pub fn capability(choice: &Choice, probe: &Probe) -> Option<FaceCapability> {
    if !choice.ready || probe.backend != choice.backend {
        return None;
    }
    Some(FaceCapability { camera: choice.camera, liveness: choice.camera == Camera::Infrared && probe.liveness })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn node(kind: Camera) -> CameraNode {
        CameraNode { device: PathBuf::from("/dev/video0"), name: String::new(), usb_id: None, formats: vec![], kind }
    }

    fn ready(backend: Backend, ir: bool, rgb: bool, liveness: bool) -> Probe {
        Probe {
            backend,
            installed: true,
            daemon: Daemon::Running,
            enrolled: Some(1),
            ir: Some(ir),
            rgb: Some(rgb),
            liveness,
            notes: vec![],
        }
    }

    #[test]
    fn ir_goes_to_irlume() {
        let cams = [node(Camera::Rgb), node(Camera::Infrared)];
        let c = choose(&cams, &ready(Backend::Irlume, true, true, true), &Probe::missing(Backend::Gaze)).unwrap();
        assert_eq!((c.backend, c.camera, c.ready), (Backend::Irlume, Camera::Infrared, true));
        let cap = capability(&c, &ready(Backend::Irlume, true, true, true)).unwrap();
        assert!(cap.liveness);

        // Nothing installed yet: still Irlume, not ready.
        let c = choose(&cams, &Probe::missing(Backend::Irlume), &Probe::missing(Backend::Gaze)).unwrap();
        assert_eq!((c.backend, c.ready), (Backend::Irlume, false));
    }

    #[test]
    fn rgb_only_goes_to_gaze_and_is_never_live() {
        let cams = [node(Camera::Rgb)];
        let gaze = ready(Backend::Gaze, false, true, true);
        let c = choose(&cams, &Probe::missing(Backend::Irlume), &gaze).unwrap();
        assert_eq!((c.backend, c.camera, c.ready), (Backend::Gaze, Camera::Rgb, true));
        assert_eq!(capability(&c, &gaze), Some(FaceCapability { camera: Camera::Rgb, liveness: false }));
    }

    #[test]
    fn gaze_takes_over_when_irlume_cannot_drive_ir() {
        let cams = [node(Camera::Rgb), node(Camera::Infrared)];
        let c = choose(&cams, &ready(Backend::Irlume, false, true, false), &ready(Backend::Gaze, false, true, true)).unwrap();
        assert_eq!(c.backend, Backend::Gaze);
    }

    #[test]
    fn ir_without_liveness_is_presence_and_unenrolled_is_nothing() {
        let cams = [node(Camera::Infrared)];
        let no_pad = ready(Backend::Irlume, true, false, false);
        let c = choose(&cams, &no_pad, &Probe::missing(Backend::Gaze)).unwrap();
        assert_eq!(capability(&c, &no_pad), Some(FaceCapability { camera: Camera::Infrared, liveness: false }));

        let unenrolled = Probe { enrolled: Some(0), ..no_pad };
        let c = choose(&cams, &unenrolled, &Probe::missing(Backend::Gaze)).unwrap();
        assert_eq!(capability(&c, &unenrolled), None);
        assert!(choose(&[], &unenrolled, &Probe::missing(Backend::Gaze)).is_none());
    }
}

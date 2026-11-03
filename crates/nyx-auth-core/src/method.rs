use serde::{Deserialize, Serialize};

use crate::Assurance;

/// What kind of evidence a method contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Factor {
    Knowledge,
    Possession,
    Inherence,
}

/// A method as named in a policy, without hardware details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "dbus", derive(zvariant::Type), zvariant(signature = "s"))]
pub enum MethodKind {
    Password,
    Fingerprint,
    Face,
    SecurityKey,
}

impl MethodKind {
    pub const ALL: [MethodKind; 4] = [MethodKind::Face, MethodKind::Fingerprint, MethodKind::SecurityKey, MethodKind::Password];

    pub fn label(self) -> &'static str {
        match self {
            MethodKind::Password => "Password",
            MethodKind::Fingerprint => "Fingerprint",
            MethodKind::Face => "Face",
            MethodKind::SecurityKey => "Security key",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Camera {
    /// An infrared (Windows Hello) sensor.
    Infrared,
    /// An ordinary colour webcam.
    Rgb,
}

/// What a security key is asked to check before it signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyCheck {
    /// A touch: someone is holding the key. It says nothing about who.
    #[default]
    Touch,
    /// The key's own user verification (its PIN, or a sensor on the key) plus a touch.
    Verified,
}

/// A concrete method, with the properties that decide how much it proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Method {
    Password,
    Fingerprint,
    Face { camera: Camera, liveness: bool },
    SecurityKey { check: KeyCheck },
}

impl Method {
    pub fn kind(self) -> MethodKind {
        match self {
            Method::Password => MethodKind::Password,
            Method::Fingerprint => MethodKind::Fingerprint,
            Method::Face { .. } => MethodKind::Face,
            Method::SecurityKey { .. } => MethodKind::SecurityKey,
        }
    }

    pub fn factor(self) -> Factor {
        match self {
            Method::Password => Factor::Knowledge,
            Method::Fingerprint | Method::Face { .. } => Factor::Inherence,
            Method::SecurityKey { .. } => Factor::Possession,
        }
    }

    /// How much this method proves on its own.
    ///
    /// A face match counts as a factor only from an infrared camera with a liveness check;
    /// otherwise a photo or a screen may pass, so it only shows that someone is there.
    pub fn assurance(self) -> Assurance {
        match self {
            Method::Password | Method::Fingerprint => Assurance::SingleFactor,
            Method::Face { camera: Camera::Infrared, liveness: true } => Assurance::SingleFactor,
            Method::Face { .. } => Assurance::Presence,
            Method::SecurityKey { check: KeyCheck::Touch } => Assurance::SingleFactor,
            Method::SecurityKey { check: KeyCheck::Verified } => Assurance::VerifiedPossession,
        }
    }

    /// Whether a success says who is there, not just that someone is.
    pub fn verifies_identity(self) -> bool {
        match self {
            Method::SecurityKey { check: KeyCheck::Touch } => false,
            other => other.assurance() >= Assurance::SingleFactor,
        }
    }

    /// Methods that must never run for a remote (SSH) session.
    pub fn local_only(self) -> bool {
        !matches!(self, Method::Password)
    }
}

/// The face backend wired to a camera, as the adapter reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaceCapability {
    pub camera: Camera,
    pub liveness: bool,
}

/// A registered security key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub name: String,
    /// The key supports user verification (a FIDO2 PIN or on-key sensor) and has it set up.
    pub verification: bool,
}

/// What this computer can do right now, as reported by the adapters.
///
/// Only enrolled, working methods appear: a reader with no fingers enrolled is
/// `fingerprint: false`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub password: bool,
    pub fingerprint: bool,
    pub face: Option<FaceCapability>,
    pub keys: Vec<KeyInfo>,
}

impl Inventory {
    pub fn has(&self, kind: MethodKind) -> bool {
        match kind {
            MethodKind::Password => self.password,
            MethodKind::Fingerprint => self.fingerprint,
            MethodKind::Face => self.face.is_some(),
            MethodKind::SecurityKey => !self.keys.is_empty(),
        }
    }
}

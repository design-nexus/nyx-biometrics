use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Method;

/// How strongly a successful check shows that the right person is present.
///
/// The order is a floor, not an equivalence: two methods at the same level are not
/// interchangeable for anything but meeting that floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "dbus", derive(zvariant::Type), zvariant(signature = "s"))]
pub enum Assurance {
    /// Someone is there: a webcam face match, or an infrared one without a liveness check.
    Presence,
    /// One factor: a password, a fingerprint, an infrared face with liveness, or a key touch.
    SingleFactor,
    /// A security key that checked its own PIN or sensor before signing.
    VerifiedPossession,
    /// Two different factors, such as a password and a security key.
    MultiFactor,
}

impl Assurance {
    pub fn label(self) -> &'static str {
        match self {
            Assurance::Presence => "Presence only",
            Assurance::SingleFactor => "One factor",
            Assurance::VerifiedPossession => "Verified security key",
            Assurance::MultiFactor => "Two factors",
        }
    }
}

/// The methods that succeeded within one authentication.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proof {
    methods: Vec<Method>,
}

impl Proof {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, method: Method) -> Self {
        self.add(method);
        self
    }

    pub fn add(&mut self, method: Method) {
        if !self.methods.contains(&method) {
            self.methods.push(method);
        }
    }

    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    /// The level reached, or `None` when nothing succeeded.
    ///
    /// Only methods that are a factor on their own count towards two factors, so a webcam
    /// face match adds nothing to a password.
    pub fn assurance(&self) -> Option<Assurance> {
        let factors: BTreeSet<_> =
            self.methods.iter().filter(|m| m.assurance() >= Assurance::SingleFactor).map(|m| m.factor()).collect();
        if factors.len() >= 2 {
            return Some(Assurance::MultiFactor);
        }
        self.methods.iter().map(|m| m.assurance()).max()
    }

    pub fn verifies_identity(&self) -> bool {
        self.methods.iter().any(|m| m.verifies_identity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Camera, KeyCheck};

    const RGB_FACE: Method = Method::Face { camera: Camera::Rgb, liveness: true };
    const IR_FACE: Method = Method::Face { camera: Camera::Infrared, liveness: true };
    const IR_NO_LIVENESS: Method = Method::Face { camera: Camera::Infrared, liveness: false };
    const TOUCH: Method = Method::SecurityKey { check: KeyCheck::Touch };
    const VERIFIED: Method = Method::SecurityKey { check: KeyCheck::Verified };

    #[test]
    fn single_methods() {
        assert_eq!(Proof::new().assurance(), None);
        assert_eq!(Proof::new().with(RGB_FACE).assurance(), Some(Assurance::Presence));
        assert_eq!(Proof::new().with(IR_NO_LIVENESS).assurance(), Some(Assurance::Presence));
        assert_eq!(Proof::new().with(IR_FACE).assurance(), Some(Assurance::SingleFactor));
        assert_eq!(Proof::new().with(Method::Fingerprint).assurance(), Some(Assurance::SingleFactor));
        assert_eq!(Proof::new().with(TOUCH).assurance(), Some(Assurance::SingleFactor));
        assert_eq!(Proof::new().with(VERIFIED).assurance(), Some(Assurance::VerifiedPossession));
    }

    #[test]
    fn two_factors_need_two_kinds_of_evidence() {
        assert_eq!(Proof::new().with(Method::Password).with(TOUCH).assurance(), Some(Assurance::MultiFactor));
        assert_eq!(Proof::new().with(Method::Fingerprint).with(VERIFIED).assurance(), Some(Assurance::MultiFactor));
        // Two inherence checks are still one factor.
        assert_eq!(Proof::new().with(Method::Fingerprint).with(IR_FACE).assurance(), Some(Assurance::SingleFactor));
        // A webcam match isn't a factor, so it can't make a password two-factor.
        assert_eq!(Proof::new().with(Method::Password).with(RGB_FACE).assurance(), Some(Assurance::SingleFactor));
    }

    #[test]
    fn a_touch_does_not_identify() {
        assert!(!Proof::new().with(TOUCH).verifies_identity());
        assert!(!Proof::new().with(RGB_FACE).verifies_identity());
        assert!(Proof::new().with(VERIFIED).verifies_identity());
        assert!(Proof::new().with(TOUCH).with(Method::Password).verifies_identity());
    }

    #[test]
    fn only_password_may_run_remotely() {
        assert!(!Method::Password.local_only());
        for m in [Method::Fingerprint, IR_FACE, RGB_FACE, TOUCH, VERIFIED] {
            assert!(m.local_only(), "{m:?}");
        }
    }
}

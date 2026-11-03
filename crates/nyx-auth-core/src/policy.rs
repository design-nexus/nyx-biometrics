use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Assurance, Camera, Inventory, KeyCheck, Method, MethodKind, Proof, Surface};

pub const MIN_TIMEOUT_SECS: u32 = 5;
pub const MAX_TIMEOUT_SECS: u32 = 120;

/// How the method to try is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Selection {
    /// Every available method is offered at once, where the surface allows it, and
    /// otherwise tried in the standard order: face, fingerprint, security key, password.
    #[default]
    Automatic,
    /// Tried in the order listed in `methods`, falling back to the next one.
    Ordered,
    /// The person picks a method each time.
    Manual,
}

/// The rules for one surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SurfacePolicy {
    #[serde(default)]
    pub selection: Selection,
    /// Methods that are each enough on their own, in preference order.
    #[serde(default)]
    pub methods: Vec<MethodKind>,
    /// Methods that are only enough together, such as a password and a security key.
    #[serde(default)]
    pub require_all: Vec<MethodKind>,
    pub minimum: Assurance,
    /// Refuse methods that show someone is there without showing who, such as a key touch.
    #[serde(default)]
    pub identity_required: bool,
    /// What every security key is asked to check on this surface.
    #[serde(default)]
    pub security_key: KeyCheck,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_timeout() -> u32 {
    30
}

impl SurfacePolicy {
    pub fn password_only() -> Self {
        Self {
            selection: Selection::Automatic,
            methods: vec![MethodKind::Password],
            require_all: Vec::new(),
            minimum: Assurance::SingleFactor,
            identity_required: false,
            security_key: KeyCheck::Touch,
            timeout_secs: default_timeout(),
        }
    }

    fn concrete(&self, kind: MethodKind, inventory: &Inventory) -> Option<Method> {
        if !inventory.has(kind) {
            return None;
        }
        Some(match kind {
            MethodKind::Password => Method::Password,
            MethodKind::Fingerprint => Method::Fingerprint,
            MethodKind::Face => {
                let face = inventory.face?;
                Method::Face { camera: face.camera, liveness: face.liveness }
            }
            MethodKind::SecurityKey => Method::SecurityKey { check: self.security_key },
        })
    }

    /// Check this policy against the hardware and resolve it, or say every reason it can't
    /// be used. Nothing is dropped silently: a listed method that is too weak is an error,
    /// not a quiet omission.
    pub fn plan(&self, surface: Surface, inventory: &Inventory) -> Result<Plan, Vec<PolicyError>> {
        let mut errors = Vec::new();
        let mut alternatives = Vec::new();
        let mut unavailable = Vec::new();

        if self.methods.is_empty() && self.require_all.is_empty() {
            errors.push(PolicyError::Empty);
        }
        if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&self.timeout_secs) {
            errors.push(PolicyError::Timeout(self.timeout_secs));
        }
        for (i, kind) in self.methods.iter().enumerate() {
            if self.methods[..i].contains(kind) {
                errors.push(PolicyError::Duplicate(*kind));
            }
        }
        for (i, kind) in self.require_all.iter().enumerate() {
            if self.require_all[..i].contains(kind) {
                errors.push(PolicyError::Duplicate(*kind));
            }
        }
        if self.require_all.len() == 1 {
            errors.push(PolicyError::CombinationOfOne(self.require_all[0]));
        }

        let uses_keys = self.methods.contains(&MethodKind::SecurityKey) || self.require_all.contains(&MethodKind::SecurityKey);
        if uses_keys && self.security_key == KeyCheck::Verified {
            for key in inventory.keys.iter().filter(|k| !k.verification) {
                errors.push(PolicyError::KeyLacksVerification(key.name.clone()));
            }
        }

        for kind in &self.methods {
            let Some(method) = self.concrete(*kind, inventory) else {
                unavailable.push(*kind);
                continue;
            };
            let proof = Proof::new().with(method);
            if let Err(e) = self.accepts(&proof, *kind) {
                errors.push(e);
                continue;
            }
            alternatives.push(vec![method]);
        }

        if self.require_all.len() > 1 {
            let mut combo = Vec::new();
            for kind in &self.require_all {
                match self.concrete(*kind, inventory) {
                    Some(m) => combo.push(m),
                    None => errors.push(PolicyError::RequiredUnavailable(*kind)),
                }
            }
            if combo.len() == self.require_all.len() {
                let proof = combo.iter().fold(Proof::new(), |p, m| p.with(*m));
                let first = self.require_all[0];
                match self.accepts(&proof, first) {
                    Ok(()) => alternatives.push(combo),
                    Err(PolicyError::TooWeak { has, needs, .. }) => errors.push(PolicyError::CombinationTooWeak { has, needs }),
                    Err(e) => errors.push(e),
                }
            }
            if surface.is_system() && self.require_all.contains(&MethodKind::SecurityKey) && inventory.keys.len() < 2 {
                errors.push(PolicyError::NoBackupKey);
            }
        }

        if surface.is_system() && !alternatives.iter().any(|a| a.contains(&Method::Password)) {
            errors.push(PolicyError::NoPasswordPath(surface));
        }
        if errors.is_empty() && alternatives.is_empty() {
            errors.push(PolicyError::NothingAvailable);
        }

        if errors.is_empty() {
            Ok(Plan { surface, selection: self.selection, alternatives, unavailable, timeout_secs: self.timeout_secs })
        } else {
            Err(errors)
        }
    }

    fn accepts(&self, proof: &Proof, kind: MethodKind) -> Result<(), PolicyError> {
        let has = proof.assurance().unwrap_or(Assurance::Presence);
        if has < self.minimum {
            return Err(PolicyError::TooWeak { method: kind, has, needs: self.minimum });
        }
        if self.identity_required && !proof.verifies_identity() {
            return Err(PolicyError::NotIdentifying(kind));
        }
        Ok(())
    }

    /// Whether a completed authentication meets this policy.
    pub fn satisfied_by(&self, proof: &Proof) -> bool {
        let Some(has) = proof.assurance() else { return false };
        let allowed = proof.methods().iter().all(|m| {
            let kind = m.kind();
            let key_ok = match m {
                Method::SecurityKey { check } => *check >= self.security_key,
                _ => true,
            };
            key_ok && (self.methods.contains(&kind) || self.require_all.contains(&kind))
        });
        let combination =
            self.require_all.len() > 1 && self.require_all.iter().all(|k| proof.methods().iter().any(|m| m.kind() == *k));
        let alone = proof.methods().iter().any(|m| self.methods.contains(&m.kind()));
        allowed && (alone || combination) && has >= self.minimum && (!self.identity_required || proof.verifies_identity())
    }
}

/// A policy resolved against the hardware: each alternative is a set of methods that are
/// enough together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub surface: Surface,
    pub selection: Selection,
    pub alternatives: Vec<Vec<Method>>,
    /// Listed methods with no enrolled hardware right now. They come back when it does.
    pub unavailable: Vec<MethodKind>,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("No sign-in methods are set")]
    Empty,
    #[error("None of the methods set here are available on this computer")]
    NothingAvailable,
    #[error("{} is listed twice", .0.label())]
    Duplicate(MethodKind),
    #[error("A combination needs at least two methods, but only {} is listed", .0.label())]
    CombinationOfOne(MethodKind),
    #[error("The time limit must be between {MIN_TIMEOUT_SECS} and {MAX_TIMEOUT_SECS} seconds, not {0}")]
    Timeout(u32),
    #[error("{} only reaches “{}”, but this needs “{}”", .method.label(), .has.label(), .needs.label())]
    TooWeak { method: MethodKind, has: Assurance, needs: Assurance },
    #[error("The combination only reaches “{}”, but this needs “{}”", .has.label(), .needs.label())]
    CombinationTooWeak { has: Assurance, needs: Assurance },
    #[error("{} shows someone is there but not who, and this needs to know who", .0.label())]
    NotIdentifying(MethodKind),
    #[error("The security key “{0}” has no PIN or sensor set up, so it can't verify you")]
    KeyLacksVerification(String),
    #[error("{} is required but isn't set up", .0.label())]
    RequiredUnavailable(MethodKind),
    #[error("Register a backup security key first, so losing one doesn't lock you out")]
    NoBackupKey,
    #[error("{} must keep a way to sign in with your password", .0.label())]
    NoPasswordPath(Surface),
}

/// The policy for every surface, as stored in `~/.config/nyx/auth/policy.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicySet {
    pub login: SurfacePolicy,
    pub lock_screen: SurfacePolicy,
    pub sudo: SurfacePolicy,
    pub polkit: SurfacePolicy,
    pub vault: SurfacePolicy,
    pub app_action: SurfacePolicy,
}

impl Default for PolicySet {
    /// Password only, everywhere: what a system without Nyx Biometrics does today.
    fn default() -> Self {
        Self {
            login: SurfacePolicy::password_only(),
            lock_screen: SurfacePolicy::password_only(),
            sudo: SurfacePolicy::password_only(),
            polkit: SurfacePolicy::password_only(),
            vault: SurfacePolicy { identity_required: true, ..SurfacePolicy::password_only() },
            app_action: SurfacePolicy { identity_required: true, ..SurfacePolicy::password_only() },
        }
    }
}

impl PolicySet {
    pub fn get(&self, surface: Surface) -> &SurfacePolicy {
        match surface {
            Surface::Login => &self.login,
            Surface::LockScreen => &self.lock_screen,
            Surface::Sudo => &self.sudo,
            Surface::Polkit => &self.polkit,
            Surface::Vault => &self.vault,
            Surface::AppAction => &self.app_action,
        }
    }

    pub fn get_mut(&mut self, surface: Surface) -> &mut SurfacePolicy {
        match surface {
            Surface::Login => &mut self.login,
            Surface::LockScreen => &mut self.lock_screen,
            Surface::Sudo => &mut self.sudo,
            Surface::Polkit => &mut self.polkit,
            Surface::Vault => &mut self.vault,
            Surface::AppAction => &mut self.app_action,
        }
    }

    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("a policy always serializes")
    }

    /// What setup suggests for this hardware. It is only a suggestion: nothing changes
    /// until the person accepts it, and every surface keeps the password.
    pub fn recommended(inventory: &Inventory) -> Self {
        let mut quick = Vec::new();
        let mut strong = Vec::new();
        if let Some(face) = inventory.face {
            quick.push(MethodKind::Face);
            if face.camera == Camera::Infrared && face.liveness {
                strong.push(MethodKind::Face);
            }
        }
        if inventory.fingerprint {
            quick.push(MethodKind::Fingerprint);
            strong.push(MethodKind::Fingerprint);
        }
        if !inventory.keys.is_empty() {
            quick.push(MethodKind::SecurityKey);
            strong.push(MethodKind::SecurityKey);
        }
        let with_password = |mut v: Vec<MethodKind>| {
            v.push(MethodKind::Password);
            v
        };
        let base = SurfacePolicy::password_only();
        Self {
            login: SurfacePolicy { methods: with_password(strong.clone()), ..base.clone() },
            lock_screen: SurfacePolicy { methods: with_password(quick), minimum: Assurance::Presence, ..base.clone() },
            sudo: SurfacePolicy { methods: with_password(strong.clone()), ..base.clone() },
            polkit: SurfacePolicy { methods: with_password(strong.clone()), ..base.clone() },
            vault: SurfacePolicy {
                methods: with_password(strong.iter().copied().filter(|k| *k != MethodKind::SecurityKey).collect()),
                identity_required: true,
                ..base.clone()
            },
            app_action: SurfacePolicy {
                methods: with_password(strong.iter().copied().filter(|k| *k != MethodKind::SecurityKey).collect()),
                identity_required: true,
                ..base
            },
        }
    }

    /// Every change between two policy sets, by surface.
    pub fn changes(&self, new: &PolicySet) -> Vec<(Surface, Change)> {
        Surface::ALL.iter().flat_map(|s| Change::between(self.get(*s), new.get(*s)).into_iter().map(move |c| (*s, c))).collect()
    }

    /// What the person must prove before `new` replaces `self`, or `None` when nothing
    /// changes. A change on a surface must be approved by something that surface accepts
    /// today, so a policy can't be weakened by the methods it is about to let in.
    pub fn approval(&self, new: &PolicySet) -> Option<SurfacePolicy> {
        let changed: Vec<Surface> = {
            let mut v: Vec<Surface> = self.changes(new).into_iter().map(|(s, _)| s).collect();
            v.dedup();
            v
        };
        let strictest = changed.into_iter().map(|s| self.get(s)).max_by_key(|p| p.minimum)?;
        Some(SurfacePolicy {
            identity_required: true,
            minimum: strictest.minimum.max(Assurance::SingleFactor),
            ..strictest.clone()
        })
    }
}

/// One difference between two versions of a surface's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    MethodAdded(MethodKind),
    MethodRemoved(MethodKind),
    OrderChanged,
    SelectionChanged,
    MinimumLowered { from: Assurance, to: Assurance },
    MinimumRaised { from: Assurance, to: Assurance },
    IdentityNoLongerRequired,
    IdentityRequired,
    CombinationChanged,
    KeyCheckLowered,
    KeyCheckRaised,
    TimeoutChanged { from: u32, to: u32 },
}

impl Change {
    pub fn between(old: &SurfacePolicy, new: &SurfacePolicy) -> Vec<Change> {
        let mut out = Vec::new();
        for k in &new.methods {
            if !old.methods.contains(k) {
                out.push(Change::MethodAdded(*k));
            }
        }
        for k in &old.methods {
            if !new.methods.contains(k) {
                out.push(Change::MethodRemoved(*k));
            }
        }
        let common = |a: &[MethodKind], b: &[MethodKind]| a.iter().copied().filter(|k| b.contains(k)).collect::<Vec<_>>();
        if common(&old.methods, &new.methods) != common(&new.methods, &old.methods) {
            out.push(Change::OrderChanged);
        }
        if old.selection != new.selection {
            out.push(Change::SelectionChanged);
        }
        if new.minimum < old.minimum {
            out.push(Change::MinimumLowered { from: old.minimum, to: new.minimum });
        } else if new.minimum > old.minimum {
            out.push(Change::MinimumRaised { from: old.minimum, to: new.minimum });
        }
        match (old.identity_required, new.identity_required) {
            (true, false) => out.push(Change::IdentityNoLongerRequired),
            (false, true) => out.push(Change::IdentityRequired),
            _ => {}
        }
        let mut a = old.require_all.clone();
        let mut b = new.require_all.clone();
        a.sort();
        b.sort();
        if a != b {
            out.push(Change::CombinationChanged);
        }
        if new.security_key < old.security_key {
            out.push(Change::KeyCheckLowered);
        } else if new.security_key > old.security_key {
            out.push(Change::KeyCheckRaised);
        }
        if old.timeout_secs != new.timeout_secs {
            out.push(Change::TimeoutChanged { from: old.timeout_secs, to: new.timeout_secs });
        }
        out
    }

    /// Whether this lets someone in who couldn't get in before.
    pub fn weakens(&self) -> bool {
        match self {
            Change::MethodAdded(_)
            | Change::MinimumLowered { .. }
            | Change::IdentityNoLongerRequired
            | Change::CombinationChanged
            | Change::KeyCheckLowered => true,
            Change::TimeoutChanged { from, to } => to > from,
            Change::MethodRemoved(_)
            | Change::OrderChanged
            | Change::SelectionChanged
            | Change::MinimumRaised { .. }
            | Change::IdentityRequired
            | Change::KeyCheckRaised => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FaceCapability, KeyInfo};

    fn key(name: &str, verification: bool) -> KeyInfo {
        KeyInfo { name: name.into(), verification }
    }

    fn full() -> Inventory {
        Inventory {
            password: true,
            fingerprint: true,
            face: Some(FaceCapability { camera: Camera::Infrared, liveness: true }),
            keys: vec![key("Primary", true), key("Backup", true)],
        }
    }

    fn rgb_only() -> Inventory {
        Inventory { password: true, face: Some(FaceCapability { camera: Camera::Rgb, liveness: true }), ..Default::default() }
    }

    fn policy(methods: &[MethodKind]) -> SurfacePolicy {
        SurfacePolicy { methods: methods.to_vec(), ..SurfacePolicy::password_only() }
    }

    use MethodKind::*;

    #[test]
    fn default_is_password_only_everywhere() {
        let set = PolicySet::default();
        for s in Surface::ALL {
            assert_eq!(set.get(s).methods, vec![Password], "{s:?}");
            assert!(set.get(s).plan(s, &full()).is_ok(), "{s:?}");
        }
    }

    #[test]
    fn webcam_face_is_refused_where_one_factor_is_needed() {
        let errors = policy(&[Face, Password]).plan(Surface::Sudo, &rgb_only()).unwrap_err();
        assert_eq!(errors, vec![PolicyError::TooWeak { method: Face, has: Assurance::Presence, needs: Assurance::SingleFactor }]);
        let lock = SurfacePolicy { minimum: Assurance::Presence, ..policy(&[Face, Password]) };
        let plan = lock.plan(Surface::LockScreen, &rgb_only()).unwrap();
        assert_eq!(plan.alternatives.len(), 2);
    }

    #[test]
    fn system_surfaces_keep_the_password() {
        for s in [Surface::Login, Surface::LockScreen, Surface::Sudo, Surface::Polkit] {
            let errors = policy(&[Fingerprint]).plan(s, &full()).unwrap_err();
            assert_eq!(errors, vec![PolicyError::NoPasswordPath(s)]);
        }
        // Passwords and other app surfaces may drop it.
        assert!(policy(&[Fingerprint]).plan(Surface::Vault, &full()).is_ok());
    }

    #[test]
    fn a_touch_is_refused_where_identity_is_needed() {
        let p = SurfacePolicy { identity_required: true, ..policy(&[SecurityKey, Password]) };
        assert_eq!(p.plan(Surface::Vault, &full()).unwrap_err(), vec![PolicyError::NotIdentifying(SecurityKey)]);
        let verified = SurfacePolicy { security_key: KeyCheck::Verified, ..p };
        assert!(verified.plan(Surface::Vault, &full()).is_ok());
    }

    #[test]
    fn a_pin_policy_refuses_keys_without_a_pin() {
        let mut inv = full();
        inv.keys[1].verification = false;
        let p = SurfacePolicy { security_key: KeyCheck::Verified, ..policy(&[SecurityKey, Password]) };
        assert_eq!(p.plan(Surface::Sudo, &inv).unwrap_err(), vec![PolicyError::KeyLacksVerification("Backup".into())]);
    }

    #[test]
    fn password_and_key_together() {
        let p = SurfacePolicy {
            methods: vec![],
            require_all: vec![Password, SecurityKey],
            minimum: Assurance::MultiFactor,
            ..SurfacePolicy::password_only()
        };
        let plan = p.plan(Surface::Sudo, &full()).unwrap();
        assert_eq!(plan.alternatives, vec![vec![Method::Password, Method::SecurityKey { check: KeyCheck::Touch }]]);

        // A fingerprint alone can't be an alternative to a two-factor rule.
        let with_alt = SurfacePolicy { methods: vec![Fingerprint], ..p.clone() };
        assert!(with_alt.plan(Surface::Sudo, &full()).unwrap_err().contains(&PolicyError::TooWeak {
            method: Fingerprint,
            has: Assurance::SingleFactor,
            needs: Assurance::MultiFactor
        }));

        // With one key, losing it would lock the person out.
        let mut one_key = full();
        one_key.keys.truncate(1);
        assert_eq!(p.plan(Surface::Sudo, &one_key).unwrap_err(), vec![PolicyError::NoBackupKey]);
    }

    #[test]
    fn missing_hardware_is_unavailable_not_dropped_silently() {
        let plan = policy(&[Fingerprint, Face, Password])
            .plan(Surface::Sudo, &Inventory { password: true, ..Default::default() })
            .unwrap();
        assert_eq!(plan.alternatives, vec![vec![Method::Password]]);
        assert_eq!(plan.unavailable, vec![Fingerprint, Face]);
    }

    #[test]
    fn malformed_policies() {
        let empty = SurfacePolicy { methods: vec![], ..SurfacePolicy::password_only() };
        assert!(empty.plan(Surface::Vault, &full()).unwrap_err().contains(&PolicyError::Empty));
        let dup = policy(&[Password, Password]);
        assert!(dup.plan(Surface::Vault, &full()).unwrap_err().contains(&PolicyError::Duplicate(Password)));
        let slow = SurfacePolicy { timeout_secs: 600, ..SurfacePolicy::password_only() };
        assert!(slow.plan(Surface::Vault, &full()).unwrap_err().contains(&PolicyError::Timeout(600)));
    }

    #[test]
    fn satisfied_by() {
        let face = Method::Face { camera: Camera::Infrared, liveness: true };
        let p = policy(&[Face, Password]);
        assert!(p.satisfied_by(&Proof::new().with(face)));
        assert!(p.satisfied_by(&Proof::new().with(Method::Password)));
        // Methods the policy doesn't list don't count, even when strong.
        assert!(!p.satisfied_by(&Proof::new().with(Method::Fingerprint)));
        assert!(!p.satisfied_by(&Proof::new()));

        let pin = SurfacePolicy { security_key: KeyCheck::Verified, ..policy(&[SecurityKey]) };
        assert!(!pin.satisfied_by(&Proof::new().with(Method::SecurityKey { check: KeyCheck::Touch })));
        assert!(pin.satisfied_by(&Proof::new().with(Method::SecurityKey { check: KeyCheck::Verified })));

        let both = SurfacePolicy {
            methods: vec![],
            require_all: vec![Password, SecurityKey],
            minimum: Assurance::MultiFactor,
            ..SurfacePolicy::password_only()
        };
        assert!(!both.satisfied_by(&Proof::new().with(Method::Password)));
        assert!(both.satisfied_by(&Proof::new().with(Method::Password).with(Method::SecurityKey { check: KeyCheck::Touch })));
    }

    #[test]
    fn weakening_is_detected() {
        let old = PolicySet::default();
        let mut new = old.clone();
        new.sudo.methods.insert(0, Fingerprint);
        let changes = old.changes(&new);
        assert_eq!(changes, vec![(Surface::Sudo, Change::MethodAdded(Fingerprint))]);
        assert!(changes[0].1.weakens());
        let approval = old.approval(&new).unwrap();
        assert_eq!(approval.methods, vec![Password]);
        assert!(approval.identity_required);

        assert_eq!(old.approval(&old), None);
        assert!(!Change::MethodRemoved(Face).weakens());
        assert!(Change::KeyCheckLowered.weakens());
        assert!(Change::MinimumLowered { from: Assurance::SingleFactor, to: Assurance::Presence }.weakens());
    }

    #[test]
    fn recommended_policy_is_valid_and_keeps_passwords() {
        for inv in [full(), rgb_only(), Inventory { password: true, ..Default::default() }] {
            let set = PolicySet::recommended(&inv);
            for s in Surface::ALL {
                let plan = set.get(s).plan(s, &inv).unwrap_or_else(|e| panic!("{s:?} {inv:?}: {e:?}"));
                assert!(plan.alternatives.iter().any(|a| a == &vec![Method::Password]));
            }
        }
        // A webcam face is only suggested for the lock screen.
        let set = PolicySet::recommended(&rgb_only());
        assert!(set.lock_screen.methods.contains(&Face));
        assert!(!set.sudo.methods.contains(&Face));
    }

    #[test]
    fn toml_round_trip() {
        let set = PolicySet::recommended(&full());
        assert_eq!(PolicySet::from_toml(&set.to_toml()).unwrap(), set);
        assert!(PolicySet::from_toml("[login]\nminimum = \"single-factor\"\nbogus = 1").is_err());
    }
}

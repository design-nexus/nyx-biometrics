//! Applying PAM changes: snapshot, write, arm a rollback timer, confirm or restore.
//!
//! The helper never takes PAM text from its caller. It is given the policy, resolves it
//! against hardware it probes itself, generates with fixed templates, checks the result,
//! and only then writes, and only paths on a fixed list.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use nyx_auth_core::{PolicySet, Surface};
use nyx_auth_pam::check;
use nyx_auth_pam::generate::{self, Changes, FileChange, Files, Modules, POLKIT_DROPIN};
use serde::{Deserialize, Serialize};

use crate::fsx::{self, FsError};

pub const ROLLBACK_SECS: u32 = 120;
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PamError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error("the policy file doesn't parse: {0}")]
    Policy(String),
    #[error("{0} can't be applied: {1}")]
    Plan(&'static str, String),
    #[error("{0}")]
    Generate(String),
    #[error("the generated files failed their checks:\n{0}")]
    Check(String),
    #[error("what would be applied differs from what was previewed; preview again")]
    Changed,
    #[error("{0} isn't a file Nyx Biometrics may change")]
    NotAllowed(String),
    #[error("{0} wasn't written by Nyx Biometrics, so it won't be removed")]
    Foreign(String),
    #[error("{0} is missing; run `sudo nyx-authctl helper install` first")]
    Missing(String),
    #[error("no snapshot to restore")]
    NoSnapshot,
    #[error("the snapshot is damaged: {0}")]
    Snapshot(String),
}

/// Where everything lives; `/` in production.
pub struct Root {
    pub root: PathBuf,
}

impl Root {
    pub fn system() -> Self {
        Self { root: "/".into() }
    }

    pub fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    fn backups(&self) -> PathBuf {
        self.at("/var/lib/nyx-biometrics/pam-backups")
    }
}

impl Files for Root {
    fn etc(&self, name: &str) -> Option<String> {
        fsx::read_foreign(&self.at(&format!("/etc/pam.d/{name}")), MAX_FILE).ok().flatten()
    }
    fn vendor(&self, name: &str) -> Option<String> {
        fsx::read_foreign(&self.at(&format!("/usr/lib/pam.d/{name}")), MAX_FILE).ok().flatten()
    }
}

/// The only paths the helper writes.
fn allowed(path: &str) -> bool {
    if path == POLKIT_DROPIN {
        return true;
    }
    let Some(name) = path.strip_prefix("/etc/pam.d/") else { return false };
    let safe = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    safe && (matches!(name, "sudo" | "polkit-1" | "sddm" | "omarchy-lock-face")
        || name.starts_with("nyx-auth-")
        || name.starts_with("nyx-lock-"))
}

fn ours(text: &str) -> bool {
    text.starts_with("#%PAM-1.0\n# Nyx Biometrics:")
        || text.starts_with(nyx_auth_pam::block::CREATED_MARK)
        || text.starts_with("# Nyx Biometrics:")
}

pub fn surface_key(s: &str) -> Option<Surface> {
    [Surface::Login, Surface::LockScreen, Surface::Sudo, Surface::Polkit].into_iter().find(|x| x.key() == s)
}

/// Generate and check the changes for one surface.
pub fn prepare(
    root: &Root,
    policy_toml: &str,
    surface: Surface,
    inventory: &nyx_auth_core::Inventory,
    modules: &Modules,
) -> Result<Changes, PamError> {
    let policy = PolicySet::from_toml(policy_toml).map_err(|e| PamError::Policy(e.message().to_string()))?;
    let plan = policy
        .get(surface)
        .plan(surface, inventory)
        .map_err(|errs| PamError::Plan(surface.label(), errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ")))?;
    let changes = generate::generate(&plan, modules, root).map_err(|e| PamError::Generate(e.to_string()))?;
    check::verify(&changes, root, modules).map_err(|e| PamError::Check(e.join("\n")))?;
    for c in &changes.files {
        if !allowed(&c.path) {
            return Err(PamError::NotAllowed(c.path.clone()));
        }
    }
    Ok(changes)
}

/// A digest of the changes, so the helper applies exactly what was previewed.
pub fn fingerprint(changes: &Changes) -> String {
    let mut h = DefaultHasher::new();
    for c in &changes.files {
        c.path.hash(&mut h);
        c.contents.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

/// Only changes that do something.
pub fn effective(root: &Root, changes: &Changes) -> Vec<FileChange> {
    changes
        .files
        .iter()
        .filter(|c| {
            let current = fsx::read_foreign(&root.at(&c.path), MAX_FILE).ok().flatten();
            current != c.contents
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    /// The saved copy's file name, or `None` when the file didn't exist.
    pub saved: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub surface: String,
    pub entries: Vec<Entry>,
    pub confirmed: bool,
    pub restored: bool,
}

/// Snapshot, then write. Returns the snapshot ID; the caller arms the rollback timer.
pub fn apply(root: &Root, changes: &[FileChange], surface: Surface, id: &str) -> Result<Manifest, PamError> {
    if changes.iter().any(|c| c.contents.as_deref().is_some_and(|t| t.contains("nyx-auth-gate"))) {
        let gate = root.at(nyx_auth_pam::generate::GATE);
        if !gate.is_file() {
            return Err(PamError::Missing(nyx_auth_pam::generate::GATE.into()));
        }
    }
    let dir = root.backups().join(id);
    fsx::ensure_dir(&root.backups())?;
    fsx::ensure_dir(&dir)?;
    let mut entries = Vec::new();
    for (i, c) in changes.iter().enumerate() {
        if !allowed(&c.path) {
            return Err(PamError::NotAllowed(c.path.clone()));
        }
        let current = fsx::read_foreign(&root.at(&c.path), MAX_FILE)?;
        // Nyx's own stacks may only replace or remove what Nyx wrote; the targets (sudo,
        // polkit-1, sddm) are edited in place by design.
        let own_file =
            !matches!(c.path.as_str(), "/etc/pam.d/sudo" | "/etc/pam.d/polkit-1" | "/etc/pam.d/sddm") || c.contents.is_none();
        if own_file
            && let Some(text) = &current
            && !ours(text)
        {
            return Err(PamError::Foreign(c.path.clone()));
        }
        let saved = match current {
            Some(text) => {
                let name = format!("{i}");
                fsx::write_atomic(&dir.join(&name), &text, 0o600)?;
                Some(name)
            }
            None => None,
        };
        entries.push(Entry { path: c.path.clone(), saved });
    }
    let manifest = Manifest { id: id.into(), surface: surface.key().into(), entries, confirmed: false, restored: false };
    save(root, &manifest)?;
    // Generated stacks first, the target's include line last, so the target never points
    // at a file that isn't there yet.
    let mut order: Vec<&FileChange> = changes.iter().collect();
    order.sort_by_key(|c| !c.path.contains("/nyx-"));
    for c in order {
        match &c.contents {
            Some(text) => fsx::write_atomic(&root.at(&c.path), text, 0o644)?,
            None => fsx::remove_owned_or_foreign(&root.at(&c.path))?,
        }
    }
    Ok(manifest)
}

fn save(root: &Root, m: &Manifest) -> Result<(), PamError> {
    let text = serde_json::to_string_pretty(m).expect("manifest serializes");
    fsx::write_atomic(&root.backups().join(&m.id).join("manifest.json"), &text, 0o600)?;
    Ok(())
}

pub fn load(root: &Root, id: &str) -> Result<Manifest, PamError> {
    if !valid_id(id) {
        return Err(PamError::Snapshot("bad ID".into()));
    }
    let text = fsx::read_owned(&root.backups().join(id).join("manifest.json"), MAX_FILE)?.ok_or(PamError::NoSnapshot)?;
    serde_json::from_str(&text).map_err(|e| PamError::Snapshot(e.to_string()))
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// The newest snapshot not yet restored.
pub fn latest(root: &Root) -> Result<Manifest, PamError> {
    let mut ids: Vec<String> = fs::read_dir(root.backups())
        .map_err(|_| PamError::NoSnapshot)?
        .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
        .filter(|n| valid_id(n))
        .collect();
    ids.sort();
    ids.into_iter().rev().filter_map(|id| load(root, &id).ok()).find(|m| !m.restored).ok_or(PamError::NoSnapshot)
}

pub fn confirm(root: &Root, id: &str) -> Result<Manifest, PamError> {
    let mut m = load(root, id)?;
    m.confirmed = true;
    save(root, &m)?;
    Ok(m)
}

/// Put every file back as it was, targets first so nothing points at a missing stack.
pub fn restore(root: &Root, id: &str) -> Result<Manifest, PamError> {
    let mut m = load(root, id)?;
    let dir = root.backups().join(id);
    let mut entries = m.entries.clone();
    entries.sort_by_key(|e| e.path.contains("/nyx-"));
    for e in &entries {
        if !allowed(&e.path) {
            return Err(PamError::NotAllowed(e.path.clone()));
        }
        match &e.saved {
            Some(name) => {
                let text =
                    fsx::read_owned(&dir.join(name), MAX_FILE)?.ok_or_else(|| PamError::Snapshot(format!("{name} missing")))?;
                fsx::write_atomic(&root.at(&e.path), &text, 0o644)?;
            }
            None => fsx::remove_owned_or_foreign(&root.at(&e.path))?,
        }
    }
    m.restored = true;
    save(root, &m)?;
    Ok(m)
}

pub fn touches_dropin(changes: &[FileChange]) -> bool {
    changes.iter().any(|c| c.path == POLKIT_DROPIN)
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyx_auth_core::{Camera, FaceCapability, Inventory, KeyInfo};
    use nyx_auth_hw::face::Backend;

    const SUDO: &str = "#%PAM-1.0\nauth include system-auth\naccount include system-auth\n";
    const SYSTEM_AUTH: &str = "auth [success=1 default=bad] pam_unix.so\nauth requisite pam_deny.so\n";

    fn setup() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let root = Root { root: dir.path().into() };
        fs::create_dir_all(root.at("/etc/pam.d")).unwrap();
        fs::create_dir_all(root.at("/usr/lib/nyx-biometrics")).unwrap();
        fs::write(root.at("/etc/pam.d/sudo"), SUDO).unwrap();
        fs::write(root.at("/etc/pam.d/system-auth"), SYSTEM_AUTH).unwrap();
        fs::write(root.at(nyx_auth_pam::generate::GATE), "").unwrap();
        (dir, root)
    }

    fn inv() -> Inventory {
        Inventory {
            password: true,
            fingerprint: true,
            face: Some(FaceCapability { camera: Camera::Infrared, liveness: true }),
            keys: vec![KeyInfo { name: "A".into(), verification: false }],
        }
    }

    fn recommended() -> String {
        PolicySet::recommended(&inv()).to_toml()
    }

    #[test]
    fn apply_then_restore_is_byte_identical() {
        let (_d, root) = setup();
        let m = Modules::system(Some(Backend::Irlume));
        let changes = prepare(&root, &recommended(), Surface::Sudo, &inv(), &m).unwrap();
        let eff = effective(&root, &changes);
        assert_eq!(eff.len(), 2, "{eff:?}");
        let manifest = apply(&root, &eff, Surface::Sudo, "20261101-1").unwrap();
        assert!(fs::read_to_string(root.at("/etc/pam.d/sudo")).unwrap().contains("nyx-auth-sudo"));
        assert!(root.at("/etc/pam.d/nyx-auth-sudo").exists());

        assert_eq!(latest(&root).unwrap().id, manifest.id);
        restore(&root, &manifest.id).unwrap();
        assert_eq!(fs::read_to_string(root.at("/etc/pam.d/sudo")).unwrap(), SUDO);
        assert!(!root.at("/etc/pam.d/nyx-auth-sudo").exists());
        assert!(matches!(latest(&root), Err(PamError::NoSnapshot)));
    }

    #[test]
    fn previewed_fingerprint_is_stable() {
        let (_d, root) = setup();
        let m = Modules::system(Some(Backend::Irlume));
        let a = prepare(&root, &recommended(), Surface::Sudo, &inv(), &m).unwrap();
        let b = prepare(&root, &recommended(), Surface::Sudo, &inv(), &m).unwrap();
        assert_eq!(fingerprint(&a), fingerprint(&b));
        let other = prepare(&root, &PolicySet::default().to_toml(), Surface::Sudo, &inv(), &m).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&other));
    }

    #[test]
    fn refuses_unsafe_requests() {
        let (_d, root) = setup();
        let m = Modules::system(Some(Backend::Irlume));
        assert!(matches!(prepare(&root, "garbage", Surface::Sudo, &inv(), &m), Err(PamError::Policy(_))));

        let mut bad = PolicySet::default();
        bad.sudo.methods = vec![nyx_auth_core::MethodKind::Fingerprint];
        assert!(matches!(prepare(&root, &bad.to_toml(), Surface::Sudo, &inv(), &m), Err(PamError::Plan(..))));

        let shadow = FileChange { path: "/etc/shadow".into(), contents: Some("x".into()) };
        assert!(matches!(apply(&root, &[shadow], Surface::Sudo, "1"), Err(PamError::NotAllowed(_))));
        let traversal = FileChange { path: "/etc/pam.d/../shadow".into(), contents: Some("x".into()) };
        assert!(matches!(apply(&root, &[traversal], Surface::Sudo, "2"), Err(PamError::NotAllowed(_))));

        fs::write(root.at("/etc/pam.d/nyx-auth-foreign"), "auth required pam_unix.so\n").unwrap();
        let remove = FileChange { path: "/etc/pam.d/nyx-auth-foreign".into(), contents: None };
        assert!(matches!(apply(&root, &[remove], Surface::Sudo, "3"), Err(PamError::Foreign(_))));
        assert!(root.at("/etc/pam.d/nyx-auth-foreign").exists());

        // Omarchy may one day write its own face service; never overwrite it.
        fs::write(root.at("/etc/pam.d/omarchy-lock-face"), "auth required pam_irlume.so\n").unwrap();
        let face =
            FileChange { path: "/etc/pam.d/omarchy-lock-face".into(), contents: Some("#%PAM-1.0\n# Nyx Biometrics: x\n".into()) };
        assert!(matches!(apply(&root, &[face], Surface::LockScreen, "5"), Err(PamError::Foreign(_))));

        fs::remove_file(root.at(nyx_auth_pam::generate::GATE)).unwrap();
        let changes = prepare(&root, &recommended(), Surface::Sudo, &inv(), &m).unwrap();
        assert!(matches!(apply(&root, &effective(&root, &changes), Surface::Sudo, "4"), Err(PamError::Missing(_))));
        assert_eq!(fs::read_to_string(root.at("/etc/pam.d/sudo")).unwrap(), SUDO);
        assert!(!valid_id("../x"));
    }
}

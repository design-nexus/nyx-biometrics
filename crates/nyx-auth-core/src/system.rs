//! Where the system's own programs and files are.
//!
//! The code names them by their usual paths (`/usr/bin/pkcheck`). NixOS has no such
//! files: setuid programs are in `/run/wrappers/bin` and the rest in the system profile,
//! `/run/current-system/sw`. Both are root's. Nothing here searches PATH.

use std::path::{Path, PathBuf};

const WRAPPERS: &str = "/run/wrappers/bin";
const PROFILE: &str = "/run/current-system/sw";

/// `path` itself when it exists, else the NixOS place for it, else `path` unchanged.
/// `/usr/bin/NAME` may also be a setuid wrapper; `/usr/local/…` and `/usr/…` map to the
/// system profile.
pub fn path(path: &str) -> PathBuf {
    let usual = Path::new(path);
    if usual.exists() {
        return usual.to_path_buf();
    }
    alternatives(path).into_iter().find(|p| p.exists()).unwrap_or_else(|| usual.to_path_buf())
}

fn alternatives(path: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(name) = path.strip_prefix("/usr/bin/") {
        out.push(Path::new(WRAPPERS).join(name));
    }
    if let Some(rest) = path.strip_prefix("/usr/local/").or_else(|| path.strip_prefix("/usr/")) {
        out.push(Path::new(PROFILE).join(rest));
    }
    out
}

/// The suite program `exe` runs, if it's installed where the suite installs programs:
/// the user's `~/.local/bin`, `/usr/bin`, `/usr/local/bin`, or a folder root lists in
/// `/etc/nyx/trusted-bin` (NixOS keeps each app in its own). Nix's wrapped `.NAME-wrapped`
/// counts as `NAME`.
pub fn suite_program(exe: &Path, home: &Path) -> Option<String> {
    let mut dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/local/bin")];
    dirs.extend(nyx_peer::trusted_dirs(Path::new(nyx_peer::TRUSTED_DIRS_FILE)));
    nyx_peer::program_in(exe, &home.join(".local/bin"), &dirs)
}

/// Whether this is NixOS, where PAM and the system's files come from its configuration
/// rather than from files Nyx writes.
pub fn nixos() -> bool {
    Path::new("/etc/NIXOS").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usual_paths_map_to_the_nixos_places() {
        assert_eq!(
            alternatives("/usr/bin/pkexec"),
            [PathBuf::from("/run/wrappers/bin/pkexec"), PathBuf::from("/run/current-system/sw/bin/pkexec")]
        );
        assert_eq!(
            alternatives("/usr/local/lib/nyx-biometrics/nyx-auth-helper"),
            [PathBuf::from("/run/current-system/sw/lib/nyx-biometrics/nyx-auth-helper")]
        );
        assert_eq!(
            alternatives("/usr/share/polkit-1/actions/a.policy"),
            [PathBuf::from("/run/current-system/sw/share/polkit-1/actions/a.policy")]
        );
        assert!(alternatives("/etc/nyx-biometrics/u2f_keys").is_empty());
    }

    #[test]
    fn suite_programs_are_known_by_place() {
        let home = Path::new("/home/u");
        assert_eq!(suite_program(Path::new("/home/u/.local/bin/nyx-passwordsd"), home).as_deref(), Some("nyx-passwordsd"));
        assert_eq!(suite_program(Path::new("/usr/bin/.nyx-passwordsd-wrapped"), home).as_deref(), Some("nyx-passwordsd"));
        assert!(suite_program(Path::new("/tmp/nyx-passwordsd"), home).is_none());
        assert!(suite_program(Path::new("/home/u/.local/bin/sub/nyx-passwordsd"), home).is_none());
    }

    #[test]
    fn a_missing_file_keeps_its_usual_path() {
        assert_eq!(path("/usr/bin/nyx-no-such-program"), PathBuf::from("/usr/bin/nyx-no-such-program"));
    }
}

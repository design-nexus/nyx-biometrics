//! The Nyx login screen: Omarchy's SDDM theme with Halo for the face. `helper install` puts
//! the theme in place; `login-theme on` chooses it with one SDDM drop-in, and `off` removes
//! that drop-in, which puts Omarchy's own theme back.

use crate::fsx;
use crate::pam::Root;

pub const THEME_DIR: &str = "/usr/share/sddm/themes/nyx-biometrics";
/// Sorts after Omarchy's `99-omarchy-login.conf`, so its `[Theme]` wins.
pub const CONF: &str = "/etc/sddm.conf.d/zz-nyx-biometrics.conf";
const CONF_TEXT: &str = "# Nyx Biometrics: the login screen with face sign-in.\n\
                         # Remove with `nyx-authctl login-theme off`, not by hand.\n\
                         [Theme]\nCurrent=nyx-biometrics\n";

pub const FILES: [(&str, &str); 4] = [
    ("Main.qml", include_str!("../../../shell/sddm/nyx-biometrics/Main.qml")),
    ("AuthOverlay.qml", include_str!("../../../shell/common/AuthOverlay.qml")),
    ("metadata.desktop", include_str!("../../../shell/sddm/nyx-biometrics/metadata.desktop")),
    ("theme.conf", include_str!("../../../shell/sddm/nyx-biometrics/theme.conf")),
];

/// Whether the theme on disk is this build's.
pub fn installed(root: &Root) -> bool {
    FILES.iter().all(|(name, text)| std::fs::read_to_string(root.at(THEME_DIR).join(name)).is_ok_and(|t| t == *text))
}

/// Whether SDDM is set to use it.
pub fn chosen(root: &Root) -> bool {
    std::fs::read_to_string(root.at(CONF)).is_ok_and(|t| t == CONF_TEXT)
}

pub fn set(root: &Root, on: bool) -> Result<String, String> {
    let conf = root.at(CONF);
    if on {
        if !installed(root) {
            return Err("the login screen theme isn't installed: run nyx-authctl helper install".into());
        }
        if let Some(dir) = conf.parent() {
            fsx::ensure_dir(dir).map_err(|e| e.to_string())?;
        }
        fsx::write_atomic(&conf, CONF_TEXT, 0o644).map_err(|e| e.to_string())?;
        return Ok("on".into());
    }
    match std::fs::read_to_string(&conf) {
        Ok(t) if t == CONF_TEXT => std::fs::remove_file(&conf).map(|_| "off".into()).map_err(|e| e.to_string()),
        Ok(_) => Err(format!("{CONF} was changed by hand; leaving it")),
        Err(_) => Ok("off".into()),
    }
}

/// Writes the theme's files (as root, from `helper install`).
pub fn install(root: &Root) -> std::io::Result<()> {
    let dir = root.at(THEME_DIR);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    for (name, text) in FILES {
        let tmp = dir.join(format!(".{name}.new"));
        std::fs::write(&tmp, text)?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        std::fs::rename(&tmp, dir.join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let root = Root { root: dir.path().into() };
        (dir, root)
    }

    #[test]
    fn on_needs_the_theme_and_off_puts_omarchy_back() {
        let (_dir, root) = scratch();
        assert!(set(&root, true).is_err());
        install(&root).unwrap();
        assert!(installed(&root));
        assert_eq!(set(&root, true).unwrap(), "on");
        assert!(chosen(&root));
        assert_eq!(set(&root, false).unwrap(), "off");
        assert!(!root.at(CONF).exists());
        assert_eq!(set(&root, false).unwrap(), "off");
    }

    #[test]
    fn leaves_a_hand_edited_dropin() {
        let (_dir, root) = scratch();
        std::fs::create_dir_all(root.at("/etc/sddm.conf.d")).unwrap();
        std::fs::write(root.at(CONF), "[Theme]\nCurrent=other\n").unwrap();
        assert!(set(&root, false).is_err());
        assert!(root.at(CONF).exists());
    }

    #[test]
    fn sorts_after_omarchy() {
        let ours = std::path::Path::new(CONF).file_name().unwrap().to_str().unwrap();
        assert!(ours > "99-omarchy-login.conf");
    }

    #[test]
    fn theme_carries_the_shared_overlay() {
        assert!(FILES[0].1.contains("AuthOverlay {"));
        assert!(FILES[1].1.contains("property string phase"));
    }
}

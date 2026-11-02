//! Security-key registrations: Nyx's pam_u2f authfile and the names beside it.

use std::path::{Path, PathBuf};

use nyx_auth_hw::u2f::{self, AuthFile, KeyName, Names, Role};

use crate::fsx::{self, FsError};

const MAX_FILE: u64 = 256 * 1024;
pub const MAX_NAME_CHARS: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error(transparent)]
    AuthFile(#[from] u2f::AuthFileError),
    #[error("the names file is damaged: {0}")]
    Names(String),
    #[error("a name must be 1 to {MAX_NAME_CHARS} printable characters")]
    BadName,
    #[error("there's nothing to import")]
    NothingToImport,
}

/// Where the files live; `/` in production, a temporary directory in tests.
pub struct Store {
    pub authfile: PathBuf,
    pub names_dir: PathBuf,
    pub omarchy_authfile: PathBuf,
}

impl Store {
    pub fn system() -> Self {
        Self::under(Path::new("/"))
    }

    pub fn under(root: &Path) -> Self {
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        Self { authfile: at(u2f::AUTHFILE), names_dir: at(u2f::NAMES_DIR), omarchy_authfile: at(u2f::OMARCHY_AUTHFILE) }
    }

    fn names_path(&self, user: &str) -> PathBuf {
        self.names_dir.join(format!("{user}.toml"))
    }

    fn load(&self, user: &str) -> Result<(AuthFile, Names), KeyError> {
        let file = AuthFile::parse(&fsx::read_owned(&self.authfile, MAX_FILE)?.unwrap_or_default())?;
        let names = match fsx::read_owned(&self.names_path(user), MAX_FILE)? {
            Some(t) => Names::parse(&t).map_err(|e| KeyError::Names(e.message().to_string()))?,
            None => Names::default(),
        };
        Ok((file, names))
    }

    fn save(&self, user: &str, file: &AuthFile, names: &Names) -> Result<(), KeyError> {
        fsx::write_atomic(&self.authfile, &file.to_string(), 0o644)?;
        let ids: Vec<&str> = file.credentials(user).iter().map(|c| c.id()).collect();
        let mut names = names.clone();
        names.keys.retain(|k| ids.contains(&k.id.as_str()));
        if names.keys.is_empty() {
            fsx::remove_owned(&self.names_path(user))?;
        } else {
            fsx::write_atomic(&self.names_path(user), &names.to_toml(), 0o644)?;
        }
        Ok(())
    }

    /// Register one credential from `pamu2fcfg` for `user`. Returns its ID.
    pub fn add(&self, user: &str, pamu2fcfg: &str, name: &str, role: Role, today: &str) -> Result<String, KeyError> {
        let name = clean_name(name)?;
        let cred = u2f::parse_pamu2fcfg(user, pamu2fcfg.trim())?;
        let (mut file, mut names) = self.load(user)?;
        let id = cred.id().to_string();
        file.add(user, cred)?;
        names.keys.push(KeyName { id: id.clone(), name, role, added: today.into() });
        self.save(user, &file, &names)?;
        Ok(id)
    }

    pub fn remove(&self, user: &str, id: &str) -> Result<(), KeyError> {
        let (mut file, names) = self.load(user)?;
        file.remove(user, id)?;
        self.save(user, &file, &names)
    }

    pub fn rename(&self, user: &str, id: &str, name: &str, role: Role) -> Result<(), KeyError> {
        let name = clean_name(name)?;
        let (file, mut names) = self.load(user)?;
        if !file.credentials(user).iter().any(|c| c.id() == id) {
            return Err(u2f::AuthFileError::NotFound.into());
        }
        match names.keys.iter_mut().find(|k| k.id == id) {
            Some(k) => {
                k.name = name;
                k.role = role;
            }
            None => names.keys.push(KeyName { id: id.into(), name, role, added: String::new() }),
        }
        self.save(user, &file, &names)
    }

    /// Copy `user`'s registrations from Omarchy's authfile. Omarchy's file is left alone;
    /// its PAM lines are migrated separately, with consent. Returns how many were copied.
    pub fn import_omarchy(&self, user: &str, today: &str) -> Result<usize, KeyError> {
        let text = fsx::read_foreign(&self.omarchy_authfile, MAX_FILE)?.ok_or(KeyError::NothingToImport)?;
        let theirs = AuthFile::parse(&text)?;
        let (mut file, mut names) = self.load(user)?;
        let mut copied = 0;
        for (i, cred) in theirs.credentials(user).iter().enumerate() {
            let id = cred.id().to_string();
            match file.add(user, cred.clone()) {
                Ok(()) => {
                    copied += 1;
                    names.keys.push(KeyName {
                        id,
                        name: format!("Omarchy key {}", i + 1),
                        role: if i == 0 { Role::Primary } else { Role::Backup },
                        added: today.into(),
                    });
                }
                Err(u2f::AuthFileError::Duplicate) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if copied == 0 {
            return Err(KeyError::NothingToImport);
        }
        self.save(user, &file, &names)?;
        Ok(copied)
    }
}

fn clean_name(name: &str) -> Result<String, KeyError> {
    let name = name.trim();
    let count = name.chars().count();
    if count == 0 || count > MAX_NAME_CHARS || name.chars().any(|c| c.is_control()) {
        return Err(KeyError::BadName);
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const CRED_1: &str = "ken:kh1AAAAAAAAAAAAAAAAAAAA,pk1,es256,+presence+pin";
    const CRED_2: &str = "ken:kh2BBBBBBBBBBBBBBBBBBBB,pk2,es256,+presence";

    #[test]
    fn add_rename_remove() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::under(root.path());
        let id1 = store.add("ken", CRED_1, "Primary YubiKey", Role::Primary, "2026-11-01").unwrap();
        let id2 = store.add("ken", CRED_2, "Backup", Role::Backup, "2026-11-01").unwrap();
        assert!(matches!(
            store.add("ken", CRED_2, "Again", Role::Backup, "x"),
            Err(KeyError::AuthFile(u2f::AuthFileError::Duplicate))
        ));

        let text = fs::read_to_string(&store.authfile).unwrap();
        assert_eq!(text, "ken:kh1AAAAAAAAAAAAAAAAAAAA,pk1,es256,+presence+pin:kh2BBBBBBBBBBBBBBBBBBBB,pk2,es256,+presence\n");

        store.rename("ken", &id2, "Keychain key", Role::Backup).unwrap();
        let names = Names::parse(&fs::read_to_string(store.names_path("ken")).unwrap()).unwrap();
        assert_eq!(names.keys[1].name, "Keychain key");

        store.remove("ken", &id1).unwrap();
        store.remove("ken", &id2).unwrap();
        assert_eq!(fs::read_to_string(&store.authfile).unwrap(), "");
        assert!(!store.names_path("ken").exists());
    }

    #[test]
    fn only_the_callers_credentials() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::under(root.path());
        // pamu2fcfg output for another user is refused, so a caller can't add keys for root.
        assert!(store.add("ken", "root:kh9ZZZZZZZZZZZZZZZZZZZZ,pk,es256,+presence", "Mine", Role::Primary, "d").is_err());
        assert!(store.add("ken", CRED_1, "bad\nname", Role::Primary, "d").is_err());
        assert!(store.add("ken", CRED_1, "", Role::Primary, "d").is_err());
        assert!(!store.authfile.exists());
    }

    #[test]
    fn import_from_omarchy() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::under(root.path());
        assert!(matches!(store.import_omarchy("ken", "d"), Err(KeyError::NothingToImport)));
        fs::create_dir_all(store.omarchy_authfile.parent().unwrap()).unwrap();
        fs::write(&store.omarchy_authfile, format!("{CRED_1}\neve:kh7CCCCCCCCCCCCCCCCCCCC,pk7,es256,+presence\n")).unwrap();
        assert_eq!(store.import_omarchy("ken", "d").unwrap(), 1);
        assert!(matches!(store.import_omarchy("ken", "d"), Err(KeyError::NothingToImport)));
        let file = AuthFile::parse(&fs::read_to_string(&store.authfile).unwrap()).unwrap();
        assert_eq!(file.credentials("ken").len(), 1);
        assert!(file.credentials("eve").is_empty(), "other users' keys aren't copied");
        assert!(store.omarchy_authfile.exists(), "Omarchy's file is left alone");
    }
}

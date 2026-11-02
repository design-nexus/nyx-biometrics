//! pam_u2f registrations, and the names Nyx gives them.
//!
//! The authfile is pam_u2f's own format, one line per user:
//! `user:keyHandle,publicKey,coseType,options:keyHandle,…`. It stays root-owned and
//! world-readable (the lock screen's PAM context runs as the user), so a process running as
//! the user can't add its own key. Names and roles live beside it in a TOML file, because
//! pam_u2f's format has nowhere to put them.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Where Nyx keeps registrations. Omarchy's `/etc/fido2/fido2` is read for migration only.
pub const AUTHFILE: &str = "/etc/nyx-biometrics/u2f_keys";
pub const NAMES_DIR: &str = "/etc/nyx-biometrics/keys";
pub const OMARCHY_AUTHFILE: &str = "/etc/fido2/fido2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub key_handle: String,
    pub public_key: String,
    pub cose_type: String,
    /// pam_u2f's flags as written, such as `+presence+pin`.
    pub options: String,
}

impl Credential {
    /// The key checked its PIN or sensor when this credential was made, and pam_u2f will
    /// ask for it again.
    pub fn verification(&self) -> bool {
        self.options.split('+').any(|f| f == "pin" || f == "verification")
    }

    /// A short, stable label for logs and the names file. Not secret, but shorter.
    pub fn id(&self) -> &str {
        let end = self.key_handle.char_indices().nth(16).map(|(i, _)| i).unwrap_or(self.key_handle.len());
        &self.key_handle[..end]
    }

    fn parse(field: &str) -> Result<Self, AuthFileError> {
        let parts: Vec<&str> = field.split(',').collect();
        match parts.as_slice() {
            [kh, pk, ty, opts] => {
                Ok(Self { key_handle: (*kh).into(), public_key: (*pk).into(), cose_type: (*ty).into(), options: (*opts).into() })
            }
            [kh, pk, ty] => {
                Ok(Self { key_handle: (*kh).into(), public_key: (*pk).into(), cose_type: (*ty).into(), options: String::new() })
            }
            _ => Err(AuthFileError::Malformed(field.chars().take(24).collect())),
        }
    }

    fn validate(&self) -> Result<(), AuthFileError> {
        let fields = [&self.key_handle, &self.public_key, &self.cose_type];
        let clean = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c));
        if fields.iter().all(|f| clean(f)) && (self.options.is_empty() || clean(&self.options)) {
            Ok(())
        } else {
            Err(AuthFileError::Malformed(self.id().to_string()))
        }
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{},{}", self.key_handle, self.public_key, self.cose_type)?;
        if !self.options.is_empty() {
            write!(f, ",{}", self.options)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthFileError {
    #[error("a registration starting “{0}” isn't in pam_u2f's format")]
    Malformed(String),
    #[error("“{0}” isn't a valid user name")]
    BadUser(String),
    #[error("this key is already registered")]
    Duplicate,
    #[error("no key registered with that ID")]
    NotFound,
}

/// The whole authfile, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthFile {
    users: Vec<(String, Vec<Credential>)>,
}

pub fn valid_user(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl AuthFile {
    pub fn parse(text: &str) -> Result<Self, AuthFileError> {
        let mut users: Vec<(String, Vec<Credential>)> = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut fields = line.split(':');
            let user = fields.next().unwrap_or_default();
            if !valid_user(user) {
                return Err(AuthFileError::BadUser(user.into()));
            }
            let creds = fields.map(Credential::parse).collect::<Result<Vec<_>, _>>()?;
            match users.iter_mut().find(|(u, _)| u == user) {
                Some((_, existing)) => existing.extend(creds),
                None => users.push((user.into(), creds)),
            }
        }
        Ok(Self { users })
    }

    pub fn credentials(&self, user: &str) -> &[Credential] {
        self.users.iter().find(|(u, _)| u == user).map(|(_, c)| c.as_slice()).unwrap_or(&[])
    }

    pub fn add(&mut self, user: &str, cred: Credential) -> Result<(), AuthFileError> {
        if !valid_user(user) {
            return Err(AuthFileError::BadUser(user.into()));
        }
        cred.validate()?;
        if self.users.iter().any(|(_, cs)| cs.iter().any(|c| c.key_handle == cred.key_handle)) {
            return Err(AuthFileError::Duplicate);
        }
        match self.users.iter_mut().find(|(u, _)| u == user) {
            Some((_, creds)) => creds.push(cred),
            None => self.users.push((user.into(), vec![cred])),
        }
        Ok(())
    }

    pub fn remove(&mut self, user: &str, id: &str) -> Result<Credential, AuthFileError> {
        let (_, creds) = self.users.iter_mut().find(|(u, _)| u == user).ok_or(AuthFileError::NotFound)?;
        let pos = creds.iter().position(|c| c.id() == id).ok_or(AuthFileError::NotFound)?;
        let removed = creds.remove(pos);
        self.users.retain(|(_, cs)| !cs.is_empty());
        Ok(removed)
    }
}

impl fmt::Display for AuthFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (user, creds) in &self.users {
            write!(f, "{user}")?;
            for c in creds {
                write!(f, ":{c}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Parse one line of `pamu2fcfg` output for `user`.
pub fn parse_pamu2fcfg(user: &str, text: &str) -> Result<Credential, AuthFileError> {
    let file = AuthFile::parse(text)?;
    match (file.users.len(), file.credentials(user)) {
        (1, [cred]) => {
            cred.validate()?;
            Ok(cred.clone())
        }
        _ => Err(AuthFileError::Malformed(text.chars().take(24).collect())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    #[default]
    Primary,
    Backup,
}

/// What Nyx knows about one registered key that pam_u2f doesn't.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct KeyName {
    /// [`Credential::id`].
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub role: Role,
    /// Day it was registered, `YYYY-MM-DD`.
    #[serde(default)]
    pub added: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Names {
    #[serde(default, rename = "key")]
    pub keys: Vec<KeyName>,
}

impl Names {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("names always serialize")
    }

    pub fn name_of(&self, cred: &Credential) -> Option<&KeyName> {
        self.keys.iter().find(|k| k.id == cred.id())
    }
}

/// Registered keys as the policy engine sees them.
pub fn key_infos(file: &AuthFile, names: &Names, user: &str) -> Vec<nyx_auth_core::KeyInfo> {
    file.credentials(user)
        .iter()
        .enumerate()
        .map(|(i, c)| nyx_auth_core::KeyInfo {
            name: names.name_of(c).map(|n| n.name.clone()).unwrap_or_else(|| format!("Security key {}", i + 1)),
            verification: c.verification(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str =
        "ken:kh1AAAAAAAAAAAAAAAAAAAA,pk1BBBB,es256,+presence:kh2CCCCCCCCCCCCCCCCCCCC,pk2DDDD,es256,+presence+pin\n";

    #[test]
    fn round_trips_pam_u2f_lines() {
        let file = AuthFile::parse(LINE).unwrap();
        let creds = file.credentials("ken");
        assert_eq!(creds.len(), 2);
        assert!(!creds[0].verification());
        assert!(creds[1].verification());
        assert_eq!(file.to_string(), LINE);
        assert!(file.credentials("nobody").is_empty());
    }

    #[test]
    fn add_and_remove() {
        let mut file = AuthFile::parse(LINE).unwrap();
        let new = parse_pamu2fcfg("ken", "ken:kh3EEEEEEEEEEEEEEEEEEEE,pk3FFFF,es256,+presence+pin").unwrap();
        file.add("ken", new.clone()).unwrap();
        assert_eq!(file.add("ken", new.clone()), Err(AuthFileError::Duplicate));
        assert_eq!(file.credentials("ken").len(), 3);
        let removed = file.remove("ken", new.id()).unwrap();
        assert_eq!(removed, new);
        assert_eq!(file.remove("ken", "missing"), Err(AuthFileError::NotFound));
        file.remove("ken", "kh1AAAAAAAAAAAAA").unwrap();
        file.remove("ken", "kh2CCCCCCCCCCCCC").unwrap();
        assert_eq!(file.to_string(), "");
    }

    #[test]
    fn refuses_injection() {
        let mut file = AuthFile::default();
        let bad = Credential {
            key_handle: "kh\nroot".into(),
            public_key: "pk".into(),
            cose_type: "es256".into(),
            options: String::new(),
        };
        assert!(file.add("ken", bad).is_err());
        let colon =
            Credential { key_handle: "kh:x".into(), public_key: "pk".into(), cose_type: "es256".into(), options: String::new() };
        assert!(file.add("ken", colon).is_err());
        let ok =
            Credential { key_handle: "kh".into(), public_key: "pk".into(), cose_type: "es256".into(), options: String::new() };
        assert_eq!(file.add("Root!", ok), Err(AuthFileError::BadUser("Root!".into())));
        assert!(parse_pamu2fcfg("ken", "ken:a,b,es256:c,d,es256").is_err());
        assert!(parse_pamu2fcfg("ken", "eve:a,b,es256").is_err());
    }

    #[test]
    fn names_and_key_infos() {
        let file = AuthFile::parse(LINE).unwrap();
        let names = Names::parse("[[key]]\nid = \"kh2CCCCCCCCCCCCC\"\nname = \"Backup YubiKey\"\nrole = \"backup\"\n").unwrap();
        let infos = key_infos(&file, &names, "ken");
        assert_eq!(infos[0].name, "Security key 1");
        assert!(!infos[0].verification);
        assert_eq!(infos[1].name, "Backup YubiKey");
        assert!(infos[1].verification);
        assert_eq!(Names::parse(&names.to_toml()).unwrap(), names);
    }
}

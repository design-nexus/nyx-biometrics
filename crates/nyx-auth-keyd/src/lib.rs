//! nyx-auth-keyd: hands a TPM-sealed secret back to the app that sealed it, after polkit
//! confirms the user.
//!
//! It exists so a face or fingerprint can unlock something encrypted (Nyx Passwords' user
//! key) without the key ever sitting in the user's session at rest. A program running as
//! the user can't skip the check: the sealed file is root's, the TPM unseals only for root,
//! and the release waits on polkit's answer for the asking process.

use std::path::{Path, PathBuf};

use nyx_auth_proto::keyd::{MAX_PURPOSE_CHARS, Reply, Request, valid_name};
use zeroize::Zeroizing;

/// Apps that may keep secrets here, by executable name.
pub const CLIENTS: &[&str] = &["nyx-passwordsd"];
pub const STATE: &str = "/var/lib/nyx-biometrics/vault";
pub const ACTION_LOAD: &str = "io.github.design_nexus.nyx.auth.unlock";
pub const ACTION_STORE: &str = "io.github.design_nexus.nyx.auth.enroll-unlock";

/// Who is on the other end of the socket, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: u32,
    /// Process start time (jiffies since boot), so a reused pid can't stand in.
    pub start_time: u64,
    /// The executable's file name.
    pub exe: String,
}

/// The parts that touch the system, so tests can stand in for polkit and the TPM.
pub trait System {
    /// Ask polkit whether `peer` may do `action`, letting it ask the user.
    fn authorize(&self, peer: &Peer, action: &str, message: &str) -> Result<bool, String>;
    fn seal(&self, credential: &str, secret: &[u8]) -> Result<Vec<u8>, String>;
    fn unseal(&self, credential: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String>;
}

pub struct Keyd<'a> {
    pub state: PathBuf,
    pub system: &'a dyn System,
}

fn clean_purpose(p: &str) -> Option<String> {
    let p = p.trim();
    (!p.is_empty() && p.chars().count() <= MAX_PURPOSE_CHARS && !p.chars().any(char::is_control)).then(|| p.to_string())
}

impl Keyd<'_> {
    fn dir(&self, peer: &Peer) -> PathBuf {
        self.state.join(peer.uid.to_string())
    }

    fn path(&self, peer: &Peer, name: &str) -> PathBuf {
        self.dir(peer).join(format!("{}-{name}.cred", peer.exe))
    }

    /// Bound into the sealed blob, so a file copied to another name, app or user won't open.
    fn credential(peer: &Peer, name: &str) -> String {
        format!("nyx-{}-{}-{name}", peer.uid, peer.exe)
    }

    pub fn handle(&self, peer: &Peer, request: Request) -> Reply {
        if !CLIENTS.contains(&peer.exe.as_str()) {
            return Reply::err("refused", "this program may not keep secrets here");
        }
        match request {
            Request::Exists { name } if valid_name(&name) => {
                Reply { exists: Some(self.path(peer, &name).is_file()), ..Reply::ok() }
            }
            Request::Clear { name } if valid_name(&name) => match std::fs::remove_file(self.path(peer, &name)) {
                Ok(()) => Reply::ok(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Reply::ok(),
                Err(e) => Reply::err("failed", e.to_string()),
            },
            Request::Store { name, secret } if valid_name(&name) => {
                let secret = Zeroizing::new(secret);
                if secret.is_empty() || secret.len() > 8 * 1024 {
                    return Reply::err("bad-request", "the secret is empty or too long");
                }
                match self.system.authorize(
                    peer,
                    ACTION_STORE,
                    "Confirm it's you to turn on unlocking Nyx Passwords with your face",
                ) {
                    Ok(true) => {}
                    Ok(false) => return Reply::err("denied", "not confirmed"),
                    Err(e) => return Reply::err("failed", e),
                }
                let blob = match self.system.seal(&Self::credential(peer, &name), secret.as_bytes()) {
                    Ok(b) => b,
                    Err(e) => return Reply::err("failed", e),
                };
                match write_private(&self.dir(peer), &self.path(peer, &name), &blob) {
                    Ok(()) => Reply::ok(),
                    Err(e) => Reply::err("failed", e.to_string()),
                }
            }
            Request::Load { name, purpose } if valid_name(&name) => {
                let Some(purpose) = clean_purpose(&purpose) else {
                    return Reply::err("bad-request", "the purpose must be one short line");
                };
                let blob = match std::fs::read(self.path(peer, &name)) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Reply::err("not-found", "nothing saved"),
                    Err(e) => return Reply::err("failed", e.to_string()),
                };
                match self.system.authorize(peer, ACTION_LOAD, &purpose) {
                    Ok(true) => {}
                    Ok(false) => return Reply::err("denied", "not confirmed"),
                    Err(e) => return Reply::err("failed", e),
                }
                match self.system.unseal(&Self::credential(peer, &name), &blob) {
                    Ok(secret) => match String::from_utf8(secret.to_vec()) {
                        Ok(s) => Reply { secret: Some(s), ..Reply::ok() },
                        Err(_) => Reply::err("failed", "the saved secret is damaged"),
                    },
                    Err(e) => Reply::err("failed", e),
                }
            }
            _ => Reply::err("bad-request", "bad name"),
        }
    }
}

/// Root-only directory and file, written atomically.
pub fn write_private(dir: &Path, path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let tmp = dir.join(format!(".new-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        answer: bool,
        asked: RefCell<Vec<(String, String)>>,
    }

    impl System for Fake {
        fn authorize(&self, _peer: &Peer, action: &str, message: &str) -> Result<bool, String> {
            self.asked.borrow_mut().push((action.into(), message.into()));
            Ok(self.answer)
        }
        fn seal(&self, credential: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
            Ok([credential.as_bytes(), b"|", secret].concat())
        }
        fn unseal(&self, credential: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
            let prefix = format!("{credential}|");
            blob.strip_prefix(prefix.as_bytes()).map(|s| Zeroizing::new(s.to_vec())).ok_or_else(|| "wrong credential".into())
        }
    }

    fn peer(exe: &str, uid: u32) -> Peer {
        Peer { uid, pid: 100, start_time: 5, exe: exe.into() }
    }

    fn store(name: &str, secret: &str) -> Request {
        Request::Store { name: name.into(), secret: secret.into() }
    }

    fn load(name: &str) -> Request {
        Request::Load { name: name.into(), purpose: "Unlock Nyx Passwords".into() }
    }

    #[test]
    fn store_then_load_after_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let yes = Fake { answer: true, asked: RefCell::new(vec![]) };
        let k = Keyd { state: dir.path().into(), system: &yes };
        let p = peer("nyx-passwordsd", 1000);
        assert!(k.handle(&p, store("vault-a", "user-key")).ok);
        assert_eq!(k.handle(&p, Request::Exists { name: "vault-a".into() }).exists, Some(true));
        assert_eq!(k.handle(&p, load("vault-a")).secret.as_deref(), Some("user-key"));
        assert_eq!(yes.asked.borrow().iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(), vec![ACTION_STORE, ACTION_LOAD]);

        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dir.path().join("1000")).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn nothing_without_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let yes = Fake { answer: true, asked: RefCell::new(vec![]) };
        let no = Fake { answer: false, asked: RefCell::new(vec![]) };
        let p = peer("nyx-passwordsd", 1000);
        assert!(Keyd { state: dir.path().into(), system: &yes }.handle(&p, store("vault-a", "user-key")).ok);
        let r = Keyd { state: dir.path().into(), system: &no }.handle(&p, load("vault-a"));
        assert_eq!((r.ok, r.error.as_deref(), r.secret), (false, Some("denied"), None));
        assert!(!Keyd { state: dir.path().into(), system: &no }.handle(&p, store("vault-b", "x")).ok);
    }

    #[test]
    fn other_programs_users_and_names_are_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        let yes = Fake { answer: true, asked: RefCell::new(vec![]) };
        let k = Keyd { state: dir.path().into(), system: &yes };
        assert!(k.handle(&peer("nyx-passwordsd", 1000), store("vault-a", "user-key")).ok);

        // Another program running as the same user is refused outright.
        let r = k.handle(&peer("python3", 1000), load("vault-a"));
        assert_eq!(r.error.as_deref(), Some("refused"));
        // Another user has nothing under that name.
        assert_eq!(k.handle(&peer("nyx-passwordsd", 1001), load("vault-a")).error.as_deref(), Some("not-found"));
        // A sealed file copied to another name won't open: the name is bound in.
        std::fs::copy(dir.path().join("1000/nyx-passwordsd-vault-a.cred"), dir.path().join("1000/nyx-passwordsd-vault-b.cred"))
            .unwrap();
        assert!(!k.handle(&peer("nyx-passwordsd", 1000), load("vault-b")).ok);
        // Path tricks and odd purposes are rejected before anything is read.
        assert_eq!(k.handle(&peer("nyx-passwordsd", 1000), load("../1001/x")).error.as_deref(), Some("bad-request"));
        let r = k.handle(&peer("nyx-passwordsd", 1000), Request::Load { name: "vault-a".into(), purpose: "a\nb".into() });
        assert_eq!(r.error.as_deref(), Some("bad-request"));
    }

    #[test]
    fn clear_needs_no_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let yes = Fake { answer: true, asked: RefCell::new(vec![]) };
        let k = Keyd { state: dir.path().into(), system: &yes };
        let p = peer("nyx-passwordsd", 1000);
        k.handle(&p, store("vault-a", "user-key"));
        yes.asked.borrow_mut().clear();
        assert!(k.handle(&p, Request::Clear { name: "vault-a".into() }).ok);
        assert!(yes.asked.borrow().is_empty());
        assert_eq!(k.handle(&p, Request::Exists { name: "vault-a".into() }).exists, Some(false));
    }
}

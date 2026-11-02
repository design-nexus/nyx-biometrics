//! The key service's wire format, and a client for apps.
//!
//! One connection, one request: a JSON line in, a JSON line out. The service learns who is
//! asking from the socket (uid and process), never from the request.

use serde::{Deserialize, Serialize};

pub const SOCKET: &str = "/run/nyx-biometrics/keyd.sock";
pub const MAX_LINE: usize = 16 * 1024;
pub const MAX_PURPOSE_CHARS: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Seal `secret` under `name` for this app. Asks the user first.
    Store { name: String, secret: String },
    /// Ask the user, then return the secret sealed under `name`.
    Load { name: String, purpose: String },
    /// Whether something is sealed under `name`. Never asks.
    Exists { name: String },
    /// Forget `name`. Never asks: it only takes a way in away.
    Clear { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
    /// `denied`, `not-found`, `refused`, `bad-request`, `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Reply {
    pub fn ok() -> Self {
        Self { ok: true, secret: None, exists: None, error: None, message: None }
    }

    pub fn err(code: &str, message: impl Into<String>) -> Self {
        Self { ok: false, secret: None, exists: None, error: Some(code.into()), message: Some(message.into()) }
    }
}

/// Names are file names: lowercase letters, digits and dashes.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Send one request and read the reply. Blocks while the user is asked.
pub fn call(request: &Request) -> std::io::Result<Reply> {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(SOCKET)?;
    let mut line = serde_json::to_string(request).map_err(std::io::Error::other)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = String::new();
    BufReader::new(stream).take(MAX_LINE as u64).read_line(&mut reply)?;
    serde_json::from_str(&reply).map_err(std::io::Error::other)
}

use std::io::Read as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r = Request::Load { name: "vault-a1".into(), purpose: "Unlock Nyx Passwords".into() };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"op":"load","name":"vault-a1","purpose":"Unlock Nyx Passwords"}"#);
        assert_eq!(serde_json::to_string(&Reply::ok()).unwrap(), r#"{"ok":true}"#);
        assert!(valid_name("vault-0f3a"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("Vault"));
    }
}

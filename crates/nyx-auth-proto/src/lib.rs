//! The broker's session-bus interface, `io.github.design_nexus.nyx.Auth1`.
//!
//! A caller asks the broker to authenticate the person for one named action. The broker
//! learns who the caller is from the connection (never from the request), shows its own
//! prompt with the caller's name and the stated purpose, and answers only that caller.
//! There is no method to approve a request: only a successful authentication at the
//! prompt can, so a program can't approve what it asked for.

use serde::{Deserialize, Serialize};
use zvariant::Type;

pub use nyx_auth_core::{Assurance, MethodKind, Surface};

pub const BUS_NAME: &str = "io.github.design_nexus.nyx.Auth";
pub const OBJECT_PATH: &str = "/io/github/design_nexus/nyx/Auth";
pub const INTERFACE: &str = "io.github.design_nexus.nyx.Auth1";

/// Longest purpose text the prompt shows.
pub const MAX_PURPOSE_CHARS: usize = 160;
/// Longest a grant may last.
pub const MAX_GRANT_SECS: u32 = 300;

/// What a caller wants the person to authenticate for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Request {
    /// A reverse-DNS action the caller owns, such as
    /// `io.github.design_nexus.nyx.passwords.reveal`. Callers may only use actions under
    /// their own prefix.
    pub action: String,
    /// One sentence the prompt shows, such as "Show the password for github.com".
    pub purpose: String,
    /// Which policy applies: `vault` or `app-action`. System surfaces are PAM's.
    pub surface: Surface,
    /// How long a success stays valid for this caller and action, in seconds; 0 means it
    /// is used once. Capped at [`MAX_GRANT_SECS`].
    pub grant_secs: u32,
}

impl Request {
    /// Checks the broker applies before showing anything.
    pub fn validate(&self, caller_prefix: &str) -> Result<(), &'static str> {
        if !matches!(self.surface, Surface::Vault | Surface::AppAction) {
            return Err("only vault and app-action requests go through the broker");
        }
        if !valid_action(&self.action) {
            return Err("the action must be a reverse-DNS name");
        }
        if !self.action.starts_with(caller_prefix) || self.action.len() == caller_prefix.len() {
            return Err("the action isn't under this caller's prefix");
        }
        let purpose = self.purpose.trim();
        if purpose.is_empty() || purpose.chars().count() > MAX_PURPOSE_CHARS {
            return Err("the purpose must be one short sentence");
        }
        if purpose.chars().any(|c| c.is_control()) {
            return Err("the purpose may not contain control characters");
        }
        if self.grant_secs > MAX_GRANT_SECS {
            return Err("the grant is too long");
        }
        Ok(())
    }
}

fn valid_action(action: &str) -> bool {
    action.len() <= 255
        && action.split('.').count() >= 3
        && action.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        })
}

/// How an authentication ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "kebab-case")]
#[zvariant(signature = "s")]
pub enum Outcome {
    Granted,
    Denied,
    Cancelled,
    TimedOut,
    /// No method the policy accepts is available, or the policy can't be used.
    Unavailable,
    /// Another prompt is already showing.
    Busy,
}

/// The broker's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Reply {
    pub outcome: Outcome,
    /// The level reached; meaningful only when granted.
    pub assurance: Assurance,
    /// The methods that succeeded, for display and audit. Never secrets.
    pub methods: Vec<MethodKind>,
    /// Seconds the grant stays valid for this caller and action.
    pub grant_secs: u32,
}

/// One method as the broker sees it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct MethodStatus {
    pub kind: MethodKind,
    pub available: bool,
    pub assurance: Assurance,
    /// A short reason when unavailable, such as "No fingerprint reader found".
    pub note: String,
}

#[cfg(feature = "client")]
#[zbus::proxy(
    interface = "io.github.design_nexus.nyx.Auth1",
    default_service = "io.github.design_nexus.nyx.Auth",
    default_path = "/io/github/design_nexus/nyx/Auth"
)]
pub trait Auth {
    /// Show the prompt and wait for the person.
    fn authenticate(&self, request: Request) -> zbus::Result<Reply>;

    /// Whether this caller already holds a grant for the action, without prompting.
    /// Returns the seconds left, or 0.
    fn check(&self, action: &str) -> zbus::Result<u32>;

    /// Drop this caller's grant for the action.
    fn revoke(&self, action: &str) -> zbus::Result<()>;

    /// Close this caller's open prompt, if any.
    fn cancel(&self) -> zbus::Result<()>;

    /// Which methods exist on this computer.
    fn methods(&self) -> zbus::Result<Vec<MethodStatus>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: &str, purpose: &str) -> Request {
        Request { action: action.into(), purpose: purpose.into(), surface: Surface::Vault, grant_secs: 0 }
    }

    const PREFIX: &str = "io.github.design_nexus.nyx.passwords.";

    #[test]
    fn requests_are_scoped_to_the_caller() {
        assert!(req("io.github.design_nexus.nyx.passwords.reveal", "Show the password for github.com").validate(PREFIX).is_ok());
        assert!(req("io.github.design_nexus.nyx.settings.reveal", "x").validate(PREFIX).is_err());
        assert!(req("io.github.design_nexus.nyx.passwords.", "x").validate(PREFIX).is_err());
    }

    #[test]
    fn purposes_are_short_plain_text() {
        let action = "io.github.design_nexus.nyx.passwords.reveal";
        assert!(req(action, "  ").validate(PREFIX).is_err());
        assert!(req(action, "line\nbreak").validate(PREFIX).is_err());
        assert!(req(action, &"x".repeat(MAX_PURPOSE_CHARS + 1)).validate(PREFIX).is_err());
    }

    #[test]
    fn system_surfaces_and_long_grants_are_refused() {
        let mut r = req("io.github.design_nexus.nyx.passwords.reveal", "Show it");
        r.surface = Surface::Sudo;
        assert!(r.validate(PREFIX).is_err());
        r.surface = Surface::Vault;
        r.grant_secs = MAX_GRANT_SECS + 1;
        assert!(r.validate(PREFIX).is_err());
    }

    #[test]
    fn wire_signatures_are_stable() {
        assert_eq!(Outcome::SIGNATURE.to_string(), "s");
        assert_eq!(Surface::SIGNATURE.to_string(), "s");
        assert_eq!(Request::SIGNATURE.to_string(), "(sssu)");
        assert_eq!(Reply::SIGNATURE.to_string(), "(ssasu)");
    }
}

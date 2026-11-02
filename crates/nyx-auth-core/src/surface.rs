use serde::{Deserialize, Serialize};

/// A place where someone is asked to authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "dbus", derive(zvariant::Type), zvariant(signature = "s"))]
pub enum Surface {
    Login,
    LockScreen,
    Sudo,
    Polkit,
    Vault,
    AppAction,
}

impl Surface {
    pub const ALL: [Surface; 6] =
        [Surface::Login, Surface::LockScreen, Surface::Sudo, Surface::Polkit, Surface::Vault, Surface::AppAction];

    /// Enforced by PAM, so changes go through the root helper and the password must stay
    /// a working path.
    pub fn is_system(self) -> bool {
        matches!(self, Surface::Login | Surface::LockScreen | Surface::Sudo | Surface::Polkit)
    }

    /// The key used in policy files.
    pub fn key(self) -> &'static str {
        match self {
            Surface::Login => "login",
            Surface::LockScreen => "lock-screen",
            Surface::Sudo => "sudo",
            Surface::Polkit => "polkit",
            Surface::Vault => "vault",
            Surface::AppAction => "app-action",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Surface::Login => "Login",
            Surface::LockScreen => "Lock screen",
            Surface::Sudo => "Terminal (sudo)",
            Surface::Polkit => "Administrator prompts",
            Surface::Vault => "Passwords",
            Surface::AppAction => "Sensitive app actions",
        }
    }
}

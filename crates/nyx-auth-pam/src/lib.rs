//! PAM wiring for Nyx Biometrics.
//!
//! Stacks are generated from a resolved [`nyx_auth_core::Plan`] using a fixed set of line
//! templates; nothing here accepts PAM text from a caller. A target file such as
//! `/etc/pam.d/sudo` only ever gains a marked `include` line, so removing Nyx is removing
//! those lines.

pub mod block;
pub mod check;
pub mod diff;
pub mod gate;
pub mod generate;
pub mod notify;
pub mod pamtest;
pub mod parse;

pub use generate::{Changes, Modules, generate};

//! What authentication hardware this computer has, and what is enrolled on it.
//!
//! Every probe goes through a [`Runner`] or a filesystem root, so tests replay recorded
//! output instead of touching devices. Probes only read: none opens a camera stream,
//! claims a reader or asks a key for a touch.
//!
//! Matching itself never happens here. Faces, fingerprints and keys are verified by their
//! own PAM modules; this crate tells the policy engine what those modules can do.

pub mod camera;
pub mod cmd;
pub mod face;
pub mod fido2;
pub mod fprint;
pub mod report;
pub mod tpm;
pub mod u2f;

pub use cmd::{Output, Runner, SystemRunner};
pub use report::{Finding, Report, Status};

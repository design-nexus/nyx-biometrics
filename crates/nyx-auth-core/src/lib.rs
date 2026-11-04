//! Authentication methods, assurance levels and the policy engine.
//!
//! Nothing here touches hardware or PAM. Adapters report what the hardware can do as an
//! [`Inventory`]; a [`SurfacePolicy`] is checked against it and either resolves to a
//! [`Plan`] or is refused with a [`PolicyError`]. Refusing is the point: a policy that
//! would let a weaker method stand in for a stronger one never becomes a plan.

mod assurance;
mod method;
mod policy;
mod surface;
pub mod system;

pub use assurance::{Assurance, Proof};
pub use method::{Camera, FaceCapability, Factor, Inventory, KeyCheck, KeyInfo, Method, MethodKind};
pub use policy::{Change, Plan, PolicyError, PolicySet, Selection, SurfacePolicy};
pub use surface::Surface;

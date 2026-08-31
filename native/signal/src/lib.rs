#![deny(unsafe_code)]

use napi_derive::napi;

pub mod curve;
pub mod proto;
pub mod session;
pub mod util;
pub mod x3dh;
pub mod ratchet;

// Placeholder: module bodies will be added in subsequent tasks.
// Each module is a separate file in src/.

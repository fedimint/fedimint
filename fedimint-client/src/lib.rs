//! Client library for fedimintd

/// Module client interface definitions
pub mod module;
/// Client state machine interfaces and executor implementation
pub mod sm;

pub type GlobalClientContext = ();

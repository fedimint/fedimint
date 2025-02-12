//! Client library
//!
//! Notably previous [`crate`] became [`fedimint_client_module`] and the
//! project is gradually moving things, that are irrelevant to the interface
//! between client and client modules.

/// Re-exporting of everything from `fedimint_client_module`
///
/// This should be removed when the splitting of [`fedimint_client_module`] is
/// complete.
pub use fedimint_client_module::*;

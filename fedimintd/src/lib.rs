#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::large_futures)]

/// Module for creating `fedimintd` binary with custom modules
pub use fedimintd::*;

mod fedimintd;

pub mod envs;

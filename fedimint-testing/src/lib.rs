#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

pub mod btc;
pub mod federation;
pub mod fixtures;
pub mod gateway;
pub mod ln;
pub use fedimint_testing_core::{db, envs};
pub use ln_gateway::config::LightningModuleMode;
pub use ln_gateway::Gateway;

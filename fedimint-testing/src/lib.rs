#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::future_not_send)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::significant_drop_in_scrutinee)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::use_self)]

pub mod btc;
pub mod db;
pub mod envs;
pub mod federation;
pub mod fixtures;
pub mod gateway;
pub mod ln;

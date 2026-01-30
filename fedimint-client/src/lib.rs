//! Client library
//!
//! Notably previous [`crate`] became [`fedimint_client_module`] and the
//! project is gradually moving things, that are irrelevant to the interface
//! between client and client modules.
//!
//! # Client library for fedimintd
//!
//! This library provides a client interface to build module clients that can be
//! plugged together into a fedimint client that exposes a high-level interface
//! for application authors to integrate with.
//!
//! ## Module Clients
//! Module clients have to at least implement the
//! [`fedimint_client_module::module::ClientModule`] trait and a factory struct
//! implementing [`fedimint_client_module::module::init::ClientModuleInit`]. The
//! `ClientModule` trait defines the module types (tx inputs, outputs, etc.) as
//! well as the module's [state machines](module::sm::State).
//!
//! ### State machines
//! State machines are spawned when starting operations and drive them
//! forward in the background. All module state machines are run by a central
//! [`crate::sm::executor::Executor`]. This means typically starting an
//! operation shall return instantly.
//!
//! For example when doing a deposit the function starting it would immediately
//! return a deposit address and a [`fedimint_client_module::OperationId`]
//! (important concept, highly recommended to read the docs) while spawning a
//! state machine checking the blockchain for incoming bitcoin transactions. The
//! progress of these state machines can then be *observed* using the operation
//! id, but no further user interaction is required to drive them forward.
//!
//! ### State Machine Contexts
//! State machines have access to both a [global
//! context](`DynGlobalClientContext`) as well as to a [module-specific
//! context](fedimint_client_module::module::ClientModule::context).
//!
//! The global context provides access to the federation API and allows to claim
//! module outputs (and transferring the value into the client's wallet), which
//! can be used for refunds.
//!
//! The client-specific context can be used for other purposes, such as
//! supplying config to the state transitions or giving access to other APIs
//! (e.g. LN gateway in case of the lightning module).
//!
//! ### Extension traits
//! The modules themselves can only create inputs and outputs that then have to
//! be combined into transactions by the user and submitted via
//! [`Client::finalize_and_submit_transaction`]. To make this easier most module
//! client implementations contain an extension trait which is implemented for
//! [`Client`] and allows to create the most typical fedimint transactions with
//! a single function call.
//!
//! To observe the progress each high level operation function should be
//! accompanied by one returning a stream of high-level operation updates.
//! Internally that stream queries the state machines belonging to the
//! operation to determine the high-level operation state.
//!
//! ### Primary Modules
//! Not all modules have the ability to hold money for long. E.g. the lightning
//! module and its smart contracts are only used to incentivize LN payments, not
//! to hold money. The mint module on the other hand holds e-cash note and can
//! thus be used to fund transactions and to absorb change. Module clients with
//! this ability should implement
//! [`fedimint_client_module::ClientModule::supports_being_primary`] and related
//! methods.
//!
//! For a example of a client module see [the mint client](https://github.com/fedimint/fedimint/blob/master/modules/fedimint-mint-client/src/lib.rs).
//!
//! ## Client
//! The [`Client`] struct is the main entry point for application authors. It is
//! constructed using its builder which can be obtained via [`Client::builder`].
//! The supported module clients have to be chosen at compile time while the
//! actually available ones will be determined by the config loaded at runtime.
//!
//! For a hacky instantiation of a complete client see the [`ng` subcommand of `fedimint-cli`](https://github.com/fedimint/fedimint/blob/55f9d88e17d914b92a7018de677d16e57ed42bf6/fedimint-cli/src/ng.rs#L56-L73).

/// Federation Api announcement handling
mod api_announcements;

/// Guardian metadata handling
mod guardian_metadata;

/// Core [`Client`]
mod client;

/// Client backup
pub mod backup;

/// Database keys used by the client
pub mod db;

/// Management of meta fields
pub mod meta;

pub mod oplog;

pub mod module_init;

pub mod sm;
pub use client::Client;
pub use client::builder::{ClientBuilder, ClientPreview, RootSecret};
pub use client::handle::{ClientHandle, ClientHandleArc};
pub use fedimint_client_module as module;
/// Re-exporting of everything from `fedimint_client_module`
///
/// This should be removed when the splitting of [`fedimint_client_module`] is
/// complete.
pub use fedimint_client_module::*;

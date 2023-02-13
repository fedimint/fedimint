//! ### Why make a fork of `LnGateway` : copy code of `../src/lib.rs` to `./gateway.rs` ?
//! - Note: `LnGateway` is renamed to `Gateway` in this new file
//! - so we can change the constructor signature of `LnGateway`
//! - so we can change how the gateway gets HTLC intercepts. `Gateway` in
//!   `src/gateway.rs` does not implement `handle_receive_payment`. Instead,
//!   actors directly subscribe to htlc intercepts on an entirely new pattern.
//!   More on this below

//! ### Why make a fork of `GatewayActor` : copy code of `../src/actor.rs` to `./actor.rs` ?
//! - So we can change constructor signature of `GatewayActor`. Have the new
//!   actor take a reference to lnrpc, which is
//! - So we can enable direct subscription to intercepted HTLCs using the owned
//!   lnrpc
//! - API signature of the `GatewayActor` changes because it owns a reference to
//!   lnrpc, rather than expec these to be passed in at api calls.
//! - Note: Changes incoming. You can preview them at #1337

pub mod actor;
pub mod gateway;
pub mod lnrpc_client;

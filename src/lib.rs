#![feature(async_closure)]

/// Configuration structs for server and client
pub mod config;

/// The actual implementation of the federated mint
pub mod consensus;

/// The implementation of mint primitives
pub mod mint;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

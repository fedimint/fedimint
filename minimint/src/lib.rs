#![feature(async_closure)]
#![feature(iterator_fold_self)]

/// The actual implementation of the federated mint
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

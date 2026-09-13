pub mod file;
pub mod nostr;

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use frost_secp256k1::{self as frost, Identifier};

use crate::frost::session::SessionId;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error {0}")]
    Serialization(String),

    #[error("invalid receiver")]
    InvalidReceiver,

    #[error("missing package from participant {0:?}")]
    MissingPackage(frost::Identifier),

    #[error("invalid package found")]
    InvalidPackage,

    #[error("package already exist")]
    DuplicatePackage,

    #[error("timeout failed")]
    TimeoutError,
}

#[async_trait]
pub trait DkgTransport: Sync + Send {
    async fn broadcast_round1(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        package: frost::keys::dkg::round1::Package,
    ) -> Result<(), TransportError>;

    async fn recv_round1_all(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::keys::dkg::round1::Package>, TransportError>;

    async fn send_round2(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        receiver: &Identifier,
        package: frost::keys::dkg::round2::Package,
    ) -> Result<(), TransportError>;

    async fn recv_round2(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::keys::dkg::round2::Package>, TransportError>;
}

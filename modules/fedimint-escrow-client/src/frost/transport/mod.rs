pub mod file;
pub mod iroh;

use std::collections::BTreeMap;
use std::error::Error;
use std::time::Duration;

use async_trait::async_trait;
use frost_secp256k1::{self as frost, Identifier};

use crate::frost::session::SessionId;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid receiver")]
    InvalidReceiver,

    #[error("session mismatch: expected {expected:?}, actual {actual:?}")]
    SessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },

    #[error("transport timeout")]
    TimeoutError,

    #[error("backend transport error: {0}")]
    Backend(#[source] Box<dyn Error + Send + Sync>),
}

impl TransportError {
    pub fn backend<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Backend(Box::new(error))
    }
}

impl From<anyhow::Error> for TransportError {
    fn from(e: anyhow::Error) -> Self {
        // anyhow::Error converts into Box<dyn Error + Send + Sync>
        Self::Backend(e.into())
    }
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

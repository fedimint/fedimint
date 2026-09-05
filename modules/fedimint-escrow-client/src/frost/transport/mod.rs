pub mod file;
pub mod nostr;

use std::collections::BTreeMap;

use frost_secp256k1 as frost;

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
    InvalidPackge,

    #[error("package already exist")]
    DuplicatePackage,
}

pub trait DkgTransport {
    type Error;

    pub fn broadcast_round1(
        &mut self,
        session_id: &SessionId,
        sender: frost::Identifier,
        package: frost::keys::dkg::round1::Package,
    ) -> Result<(), Self::Error>;

    pub fn recv_round1(
        &self,
        session_id: &SessionId,
        receiver: frost::Identifier,
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, Self::Error>;

    pub fn send_round2(
        &mut self,
        session_id: &SessionId,
        sender: frost::Identifier,
        receiver: frost::Identifier,
        package: frost::keys::dkg::round2::Package,
    ) -> Result<(), Self::Error>;

    pub fn recv_round2(
        &self,
        session_id: &SessionId,
        receiver: frost::Identifier,
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>, Self::Error>;
}

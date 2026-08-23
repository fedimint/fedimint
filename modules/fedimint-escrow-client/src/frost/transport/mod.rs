pub mod file;
pub mod nostr;

use std::collections::BTreeMap;

use frost_secp256k1 as frost;

use crate::frost::session::SessionId;

pub trait DkgTransport {
    type Error;

    fn broadcast_round1(
        &mut self,
        session_id: SessionId,
        sender: frost::Identifier,
        package: frost::keys::dkg::round1::Package,
    ) -> Result<(), Self::Error>;

    fn recv_round1(
        &self,
        session_id: SessionId,
        receiver: frost::Identifier,
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>, Self::Error>;

    fn send_round2(
        &mut self,
        session_id: SessionId,
        sender: frost::Identifier,
        receiver: frost::Identifier,
        package: frost::keys::dkg::round2::Package,
    ) -> Result<(), Self::Error>;

    fn recv_round2(
        &self,
        session_id: SessionId,
        receiver: frost::Identifier,
    ) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>, Self::Error>;
}

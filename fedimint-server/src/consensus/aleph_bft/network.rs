use async_channel::Sender;
use bitcoin::hashes::{Hash, sha256};
use fedimint_core::PeerId;
use fedimint_core::config::P2PMessage;
use fedimint_core::db::{Database, IReadDatabaseTransactionOpsTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::secp256k1::schnorr;
use fedimint_core::session_outcome::SignedSessionOutcome;
use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_CONSENSUS;
use parity_scale_codec::{Decode, Encode, IoReader};
use tracing::error;

use super::super::db::SignedSessionOutcomeKey;
use super::data_provider::UnitData;
use super::keychain::Keychain;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Hasher;

impl aleph_bft::Hasher for Hasher {
    type Hash = [u8; 32];

    fn hash(input: &[u8]) -> Self::Hash {
        input.consensus_hash::<sha256::Hash>().to_byte_array()
    }
}

pub type NetworkData = aleph_bft::NetworkData<
    Hasher,
    UnitData,
    <Keychain as aleph_bft::Keychain>::Signature,
    <Keychain as aleph_bft::MultiKeychain>::PartialMultisignature,
>;

pub struct Network {
    connections: DynP2PConnections<P2PMessage>,
    signed_outcomes_sender: Sender<(PeerId, SignedSessionOutcome)>,
    signatures_sender: Sender<(PeerId, schnorr::Signature)>,
    db: Database,
}

impl Network {
    pub fn new(
        connections: DynP2PConnections<P2PMessage>,
        signed_outcomes_sender: Sender<(PeerId, SignedSessionOutcome)>,
        signatures_sender: Sender<(PeerId, schnorr::Signature)>,
        db: Database,
    ) -> Self {
        Self {
            connections,
            signed_outcomes_sender,
            signatures_sender,
            db,
        }
    }
}

#[async_trait::async_trait]
impl aleph_bft::Network<NetworkData> for Network {
    fn send(&self, network_data: NetworkData, recipient: aleph_bft::Recipient) {
        // convert from aleph_bft::Recipient to session::Recipient
        let recipient = match recipient {
            aleph_bft::Recipient::Node(node_index) => {
                Recipient::Peer(super::to_peer_id(node_index))
            }
            aleph_bft::Recipient::Everyone => Recipient::Everyone,
        };

        self.connections
            .send(recipient, P2PMessage::Aleph(network_data.encode()));
    }

    async fn next_event(&mut self) -> Option<NetworkData> {
        loop {
            let (peer_id, message) = self.connections.receive().await?;

            match message {
                P2PMessage::Aleph(bytes) => {
                    match NetworkData::decode(&mut IoReader(bytes.as_slice())) {
                        Ok(network_data) => {
                            // in order to bound the RAM consumption of a session we have to bound
                            // the size of an individual unit in memory
                            if network_data.included_data().iter().all(UnitData::is_valid) {
                                return Some(network_data);
                            }

                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                "Received invalid unit data"
                            );
                        }
                        Err(err) => {
                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                err = %err.fmt_compact(),
                                "Failed to decode Aleph BFT network data"
                            );
                        }
                    }
                }
                P2PMessage::SessionSignature(signature) => {
                    self.signatures_sender.try_send((peer_id, signature)).ok();
                }
                P2PMessage::SessionIndex(their_session) => {
                    if let Some(outcome) = self
                        .db
                        .begin_read_transaction()
                        .await
                        .get_value(&SignedSessionOutcomeKey(their_session))
                        .await
                    {
                        self.connections.send(
                            Recipient::Peer(peer_id),
                            P2PMessage::SignedSessionOutcome(SerdeModuleEncoding::from(&outcome)),
                        );
                    }
                }
                P2PMessage::SignedSessionOutcome(encoded_outcome) => {
                    match encoded_outcome.try_into_inner(&ModuleRegistry::default()) {
                        Ok(outcome) => {
                            self.signed_outcomes_sender
                                .try_send((peer_id, outcome))
                                .ok();
                        }
                        Err(err) => {
                            error!(
                                target: LOG_CONSENSUS,
                                %peer_id,
                                err = %err.fmt_compact(),
                                "Failed to decode SignedSessionOutcome"
                            );
                        }
                    }
                }
                message => {
                    error!(
                        target: LOG_CONSENSUS,
                        %peer_id,
                        ?message,
                        "Received unexpected p2p message variant"
                    );
                }
            }
        }
    }
}

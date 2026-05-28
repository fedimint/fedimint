use std::collections::BTreeMap;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use bls12_381::{G1Projective, G2Projective, Scalar};
use fedimint_core::config::P2PMessage;
use fedimint_core::net::peers::Recipient;
use fedimint_core::{NumPeers, PeerId};
use fedimint_logging::LOG_NET_PEER_DKG;
use fedimint_server_core::config::PeerHandleOps;
use tracing::info;

use super::dkg_g1::run_dkg_g1;
use super::dkg_g2::run_dkg_g2;
use super::peer_handle::PeerHandle;

#[async_trait]
impl PeerHandleOps for PeerHandle<'_> {
    fn num_peers(&self) -> NumPeers {
        self.num_peers
    }

    async fn run_dkg_g1(&self) -> anyhow::Result<(Vec<G1Projective>, Scalar)> {
        info!(
            target: LOG_NET_PEER_DKG,
            "Running distributed key generation for group G1..."
        );

        run_dkg_g1(self.num_peers, self.identity, self.connections).await
    }

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)> {
        info!(
            target: LOG_NET_PEER_DKG,
            "Running distributed key generation for group G2..."
        );

        run_dkg_g2(self.num_peers, self.identity, self.connections).await
    }

    async fn exchange_bytes(&self, bytes: Vec<u8>) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>> {
        info!(
            target: LOG_NET_PEER_DKG,
            "Exchanging raw bytes..."
        );

        let mut peer_data: BTreeMap<PeerId, Vec<u8>> = BTreeMap::new();

        self.connections
            .send(Recipient::Everyone, P2PMessage::Encodable(bytes.clone()));

        peer_data.insert(self.identity, bytes);

        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let message = self
                .connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            match message {
                P2PMessage::Encodable(bytes) => {
                    peer_data.insert(peer, bytes);
                }
                message => {
                    anyhow::bail!("Invalid message from {peer}: {message:?}");
                }
            }
        }

        Ok(peer_data)
    }

    async fn exchange_directed(
        &self,
        mut data: BTreeMap<PeerId, Vec<u8>>,
    ) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>> {
        info!(
            target: LOG_NET_PEER_DKG,
            "Exchanging directed bytes..."
        );

        ensure!(
            !data.contains_key(&self.identity),
            "exchange_directed: input map must not contain an entry for self ({})",
            self.identity
        );
        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            ensure!(
                data.contains_key(&peer),
                "exchange_directed: missing entry for peer {peer}"
            );
        }

        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let bytes = data
                .remove(&peer)
                .expect("Validated above that every non-self peer has an entry");
            self.connections
                .send(Recipient::Peer(peer), P2PMessage::Encodable(bytes));
        }

        let mut received: BTreeMap<PeerId, Vec<u8>> = BTreeMap::new();
        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let message = self
                .connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            match message {
                P2PMessage::Encodable(bytes) => {
                    received.insert(peer, bytes);
                }
                message => {
                    anyhow::bail!("Invalid message from {peer}: {message:?}");
                }
            }
        }

        Ok(received)
    }

    fn identity(&self) -> PeerId {
        self.identity
    }
}

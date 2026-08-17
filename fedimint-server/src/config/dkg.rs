use std::collections::BTreeMap;

use anyhow::Context;
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
}

#[cfg(test)]
mod tests {
    use fedimint_core::net::peers::{DynP2PConnections, IP2PConnections, Recipient};
    use fedimint_core::{NumPeersExt, PeerId};
    use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt as _, eval_poly_g1, g1};
    use group::Curve;

    use super::{P2PMessage, PeerHandle};

    /// The p2p connections of a federation of a single guardian: there is
    /// nobody to send to and nothing will ever arrive.
    struct NoPeers;

    #[async_trait::async_trait]
    impl IP2PConnections<P2PMessage> for NoPeers {
        fn send(&self, _recipient: Recipient, _msg: P2PMessage) {}

        async fn receive(&self) -> Option<(PeerId, P2PMessage)> {
            std::future::pending().await
        }

        async fn receive_from_peer(&self, _peer: PeerId) -> Option<P2PMessage> {
            std::future::pending().await
        }
    }

    fn connections() -> DynP2PConnections<P2PMessage> {
        NoPeers.into_dyn()
    }

    /// Key generation for a federation of a single guardian has to terminate
    /// without ever receiving a message. It used to hang here, which is why
    /// production config generation fell back to a trusted dealer - the source
    /// of the deterministic key material in solo federations.
    #[tokio::test]
    async fn dkg_terminates_for_a_single_guardian() {
        let connections = connections();
        let identity = PeerId::from(0);
        let num_peers = vec![identity].to_num_peers();

        let handle = PeerHandle::new(num_peers, identity, &connections);

        let (polynomial, sks) = handle.run_dkg_g1().await.expect("DKG G1 terminates");

        assert_eq!(polynomial.len(), 1);
        assert_eq!(eval_poly_g1(&polynomial, &identity), g1(&sks).to_affine());

        handle.run_dkg_g2().await.expect("DKG G2 terminates");

        let exchanged = handle
            .exchange_encodable(42_u64)
            .await
            .expect("Exchange terminates");

        assert_eq!(exchanged, [(identity, 42_u64)].into_iter().collect());
    }

    /// The single guardian's key has to come from the OS RNG, not be derived
    /// deterministically.
    #[tokio::test]
    async fn dkg_is_not_deterministic_for_a_single_guardian() {
        let connections = connections();
        let identity = PeerId::from(0);
        let num_peers = vec![identity].to_num_peers();

        let run = || async {
            PeerHandle::new(num_peers, identity, &connections)
                .run_dkg_g1()
                .await
                .expect("DKG G1 terminates")
                .1
        };

        assert_ne!(run().await, run().await);
    }
}

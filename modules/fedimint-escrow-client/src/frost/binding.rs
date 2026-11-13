use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::BitcoinHash;
use fedimint_core::bitcoin::hashes::{HashEngine, sha256};
use fedimint_core::secp256k1::{self, Keypair, Message, PublicKey, schnorr};
use fedimint_escrow_common::x_only;
use frost_secp256k1_tr::Identifier;
use iroh::{NodeAddr, NodeId};
use serde::{Deserialize, Serialize};

use crate::frost::session::{FrostParticipant, SessionId};

/// Proof that `node_addr` belongs to the owner of `escrow_pubkey` in one
/// consortium session. Every arbiter hands its own [`PeerBinding`] to the
/// others.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerBinding {
    pub escrow_pubkey: PublicKey,
    pub node_addr: NodeAddr,
    pub signature: schnorr::Signature,
}

fn binding_digest(session_id: &SessionId, identifier: &Identifier, node_id: &NodeId) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(b"fedimint_escrow_node_binding");
    engine.input(&session_id.0);
    engine.input(&identifier.serialize());
    engine.input(node_id.as_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

impl PeerBinding {
    pub fn sign(
        session_id: &SessionId,
        escrow_key: &Keypair,
        node_addr: NodeAddr,
    ) -> anyhow::Result<Self> {
        let owner = FrostParticipant::from_pubkey(escrow_key.public_key())?;
        let digest = binding_digest(session_id, &owner.identifier, &node_addr.node_id);
        let signature =
            secp256k1::global::SECP256K1.sign_schnorr(&Message::from_digest(digest), escrow_key);

        Ok(Self {
            escrow_pubkey: escrow_key.public_key(),
            node_addr,
            signature,
        })
    }
}

/// Checks the bindings and builds the peer map for the transport.
/// A binding of ourselves is ignored so everybody can share one list.
pub fn verify_peers(
    session_id: &SessionId,
    caller: &FrostParticipant,
    own_node_id: NodeId,
    participants: &[FrostParticipant],
    bindings: Vec<PeerBinding>,
) -> anyhow::Result<BTreeMap<Identifier, NodeAddr>> {
    let mut peers = BTreeMap::new();
    let mut node_ids = BTreeSet::from([own_node_id]);

    for binding in bindings {
        let owner = FrostParticipant::from_pubkey(binding.escrow_pubkey)?;
        if owner.identifier == caller.identifier {
            continue;
        }
        anyhow::ensure!(
            participants
                .iter()
                .any(|p| p.identifier == owner.identifier),
            "binding from {:?}, who is not in the consortium",
            owner.identifier
        );

        let digest = binding_digest(session_id, &owner.identifier, &binding.node_addr.node_id);
        secp256k1::global::SECP256K1
            .verify_schnorr(
                &binding.signature,
                &Message::from_digest(digest),
                &x_only(&binding.escrow_pubkey),
            )
            .map_err(|_| anyhow::anyhow!("bad node binding for {:?}", owner.identifier))?;

        anyhow::ensure!(
            node_ids.insert(binding.node_addr.node_id),
            "node id is used by two participants"
        );
        anyhow::ensure!(
            peers.insert(owner.identifier, binding.node_addr).is_none(),
            "two bindings for {:?}",
            owner.identifier
        );
    }

    for participant in participants
        .iter()
        .filter(|p| p.identifier != caller.identifier)
    {
        anyhow::ensure!(
            peers.contains_key(&participant.identifier),
            "no node binding for {:?}",
            participant.identifier
        );
    }
    Ok(peers)
}

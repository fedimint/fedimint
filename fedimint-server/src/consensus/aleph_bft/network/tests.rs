use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aleph_bft::Network as _;
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::PeerId;
use fedimint_core::config::P2PMessage;
use fedimint_core::core::{
    DecoderBuilder, DynModuleConsensusItem, IntoDynInstance, ModuleConsensusItem, ModuleInstanceId,
    ModuleKind,
};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::net::Recipient;
use fedimint_core::net::fake::make_fake_peer_connection;
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use fedimint_core::session_outcome::{
    AcceptedItem, ConsensusItem, SessionOutcome, SignedSessionOutcome,
};

use super::{Network, PeerActivity};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
struct TestModuleItem(u64);

impl std::fmt::Display for TestModuleItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl ModuleConsensusItem for TestModuleItem {
    const KIND: ModuleKind = ModuleKind::from_static_str("session-network-test");
}

impl IntoDynInstance for TestModuleItem {
    type DynType = DynModuleConsensusItem;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleConsensusItem::from_typed(instance_id, self)
    }
}

#[tokio::test]
async fn receives_signed_session_outcome_with_module_item() {
    let local = PeerId::from(0);
    let remote = PeerId::from(1);
    let (connections, remote_connections) = make_fake_peer_connection(local, remote, 1);
    let (outcomes_sender, outcomes_receiver) = async_channel::unbounded();
    let (signatures_sender, _signatures_receiver) = async_channel::unbounded();
    let mut decoder = DecoderBuilder::default();
    decoder.with_decodable_type::<TestModuleItem>();
    let decoders = ModuleDecoderRegistry::new([(42, TestModuleItem::KIND, decoder.build())]);
    let mut network = Network::new(
        connections,
        Arc::new(Mutex::new(PeerActivity::new(local, 2.into()))),
        outcomes_sender,
        signatures_sender,
        decoders.clone(),
        Database::new(MemDatabase::new(), decoders),
    );

    let session_outcome = SessionOutcome {
        items: vec![AcceptedItem {
            item: ConsensusItem::Module(TestModuleItem(7).into_dyn(42)),
            peer: remote,
        }],
    };
    let keys =
        [local, remote].into_iter().zip([1, 2].map(|i| {
            Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[i; 32]).unwrap())
        }));
    let public_keys: BTreeMap<_, _> = keys
        .clone()
        .map(|(peer, key)| (peer, key.public_key()))
        .collect();
    let msg = Message::from_digest(
        sha256::Hash::hash(
            &[
                public_keys.consensus_hash_sha256().as_ref(),
                session_outcome.header(0).as_slice(),
            ]
            .concat(),
        )
        .to_byte_array(),
    );
    let outcome = SignedSessionOutcome {
        session_outcome,
        signatures: keys
            .map(|(peer, key)| (peer, SECP256K1.sign_schnorr_no_aux_rand(&msg, &key)))
            .collect(),
    };
    assert!(outcome.verify(&public_keys, 0));
    remote_connections.send(
        Recipient::Peer(local),
        P2PMessage::SignedSessionOutcome(SerdeModuleEncoding::from(&outcome)),
    );
    drop(remote_connections);

    assert!(network.next_event().await.is_none());
    assert_eq!(outcomes_receiver.try_recv().unwrap(), (remote, outcome));
}

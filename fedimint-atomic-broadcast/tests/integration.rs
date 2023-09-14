use std::collections::BTreeMap;
use std::time::Duration;

use async_channel::{bounded, Receiver, Sender};
use fedimint_atomic_broadcast::{AtomicBroadcast, Decision, Keychain, Message, Recipient};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{sleep, spawn};
use fedimint_core::PeerId;
use secp256k1_zkp::{rand, Secp256k1, SecretKey};
use tokio::task::JoinHandle;
use tracing::instrument;

fn to_peer_id(peer_index: usize) -> PeerId {
    u16::try_from(peer_index)
        .expect("The node index corresponds to a valid PeerId")
        .into()
}

pub fn bootstrap_keychains(peer_count: usize) -> Vec<Keychain> {
    let secp = Secp256k1::new();

    let secret_keys: Vec<(PeerId, SecretKey)> = (0..peer_count)
        .map(to_peer_id)
        .map(|peer_id| (peer_id, SecretKey::new(&mut rand::thread_rng())))
        .collect();

    let public_keys = secret_keys
        .iter()
        .map(|(peer_id, secret_key)| (*peer_id, secret_key.public_key(&secp)));

    let public_keys = BTreeMap::from_iter(public_keys);

    secret_keys
        .into_iter()
        .map(|(peer_id, secret_key)| Keychain::new(peer_id, public_keys.clone(), secret_key))
        .collect()
}

#[derive(Clone)]
pub struct Connection {
    peer_id: PeerId,
    peers: BTreeMap<PeerId, Sender<(Message, PeerId)>>,
    receiver: Receiver<(Message, PeerId)>,
}

pub fn bootstrap_connections(peer_count: usize) -> Vec<Connection> {
    let mut senders = vec![];
    let mut receivers = vec![];

    for peer_id in (0..peer_count).map(to_peer_id) {
        let (sender, receiver) = bounded(1024);

        senders.push((peer_id, sender));
        receivers.push((peer_id, receiver));
    }

    let senders = BTreeMap::from_iter(senders);

    receivers
        .into_iter()
        .map(|(peer_id, receiver)| Connection {
            peer_id,
            peers: senders.clone(),
            receiver,
        })
        .collect()
}

struct Federation {
    keychains: Vec<Keychain>,
    connections: Vec<Connection>,
    databases: Vec<Database>,
}

impl Federation {
    fn bootstrap(peer_count: usize) -> Self {
        Self {
            keychains: bootstrap_keychains(peer_count),
            connections: bootstrap_connections(peer_count),
            databases: (0..peer_count)
                .map(|_| Database::new(MemDatabase::new(), ModuleDecoderRegistry::default()))
                .collect(),
        }
    }

    fn reset_connections(&mut self) {
        self.connections = bootstrap_connections(4);
    }

    async fn start_broadcast(
        &self,
        peer_index: usize,
        session_index: u64,
    ) -> (AtomicBroadcast, JoinHandle<()>) {
        let (incoming_sender, incoming_receiver) = bounded(1024);
        let (outgoing_sender, outgoing_receiver) = bounded::<(Message, Recipient)>(1024);
        let (mempool_item_sender, mempool_item_receiver) = bounded(128);

        let connection = self.connections[peer_index].clone();

        spawn("atomic start broadcast", async move {
            loop {
                tokio::select! {
                    message = connection.receiver.recv() => {
                        if let Ok(message) = message{
                            if incoming_sender.send(message).await.is_err(){
                                break;
                            }
                        }
                    }

                    message = outgoing_receiver.recv() => {
                        if let Ok((message, recipient)) = message{
                            match recipient{
                                Recipient::Everyone => {
                                    for sender in connection.peers.values(){
                                        sender.try_send((message.clone(), connection.peer_id)).ok();
                                    }
                                }
                                Recipient::Peer(peer_id) => {
                                    connection
                                        .peers
                                        .get(&peer_id)
                                        .unwrap()
                                        .try_send((message, connection.peer_id))
                                        .ok();
                                }
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });

        spawn("mempool item sender", async move {
            let mut item: u64 = 0;
            while mempool_item_sender
                .send(item.to_le_bytes().to_vec())
                .await
                .is_ok()
            {
                item += 1;
                sleep(Duration::from_millis(100)).await;
            }
        });

        let broadcast = AtomicBroadcast::new(
            self.keychains[peer_index].clone(),
            self.databases[peer_index].clone(),
            mempool_item_receiver,
            incoming_receiver,
            outgoing_sender,
        );

        let mut ordered_item_receiver = broadcast.run_session(session_index).await;

        let decision_handle = spawn("atomic decision handler", async move {
            while let Some((ordered_item, .., decision_sender)) =
                ordered_item_receiver.recv().await.unwrap()
            {
                let decision = if ordered_item.item[0] & 1 == 0 {
                    Decision::Accept
                } else {
                    Decision::Discard
                };

                decision_sender.send(decision).unwrap();
            }
        })
        .expect("some handle on non-wasm");

        (broadcast, decision_handle)
    }
}

#[tokio::test]
#[instrument(level = "info")]
#[ignore] // https://github.com/fedimint/fedimint/issues/2741 too slow
async fn crash_recovery() {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut federation = Federation::bootstrap(4);

    for _ in 0..4 {
        // we clear the message queues
        federation.reset_connections();

        let decision_handles = vec![
            federation.start_broadcast(0, 0).await,
            federation.start_broadcast(1, 0).await,
            federation.start_broadcast(2, 0).await,
        ];

        sleep(Duration::from_secs(60)).await;

        for (broadcast, handle) in decision_handles {
            handle.abort();
            handle.await.ok();
            broadcast.shutdown().await;
        }
    }

    let decision_handles = vec![
        federation.start_broadcast(0, 0).await,
        federation.start_broadcast(1, 0).await,
        federation.start_broadcast(2, 0).await,
        federation.start_broadcast(3, 0).await,
    ];

    for (.., handle) in decision_handles {
        handle.await.unwrap();
    }
}

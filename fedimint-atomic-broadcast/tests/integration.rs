use std::collections::BTreeMap;
use std::time::Duration;

use async_channel::{bounded, Receiver, Sender};
use fedimint_atomic_broadcast::{Decision, Keychain, Message, OrderedItem, Recipient, Shutdown};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::PeerId;
use secp256k1::{rand, Secp256k1, SecretKey};
use tokio::sync::mpsc::channel;
use tokio::sync::watch;
use tokio::task::JoinHandle;

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
        .map(|(peer_id, secret_key)| (peer_id.clone(), secret_key.x_only_public_key(&secp).0));

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
        let (sender, receiver) = async_channel::bounded(1024);

        senders.push((peer_id, sender));
        receivers.push((peer_id, receiver));
    }

    let senders = BTreeMap::from_iter(senders.into_iter());

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
    shutdown_receiver: watch::Receiver<Option<(u64, Duration)>>,
}

impl Federation {
    fn bootstrap(
        peer_count: usize,
        shutdown_receiver: watch::Receiver<Option<(u64, Duration)>>,
    ) -> Self {
        Self {
            keychains: bootstrap_keychains(peer_count),
            connections: bootstrap_connections(peer_count),
            databases: (0..peer_count)
                .map(|_| Database::new(MemDatabase::new(), ModuleDecoderRegistry::default()))
                .collect(),
            shutdown_receiver,
        }
    }

    fn reset_connections(&mut self) {
        self.connections = bootstrap_connections(4);
    }

    fn start_broadcast(
        &self,
        peer_index: usize,
        session_index: u64,
    ) -> (JoinHandle<Shutdown>, JoinHandle<()>) {
        let (incoming_sender, incoming_receiver) = bounded(1024);
        let (outgoing_sender, outgoing_receiver) = bounded::<(Message, Recipient)>(1024);
        let (mempool_item_sender, mempool_item_receiver) = bounded(128);
        let (ordered_item_sender, mut ordered_item_receiver) = channel::<OrderedItem>(1);

        let connection = self.connections[peer_index].clone();

        tokio::spawn(async move {
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

        tokio::spawn(async move {
            let mut item: u64 = 0;
            while mempool_item_sender
                .send(item.to_le_bytes().to_vec())
                .await
                .is_ok()
            {
                item += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });

        let decision_handle = tokio::spawn(async move {
            while let Some(ordered_item) = ordered_item_receiver.recv().await {
                let decision = if ordered_item.item[0] & 1 == 0 {
                    Decision::Accept
                } else {
                    Decision::Discard
                };

                ordered_item.decision_sender.send(decision).unwrap();
            }
        });

        let broadcast_handle = tokio::spawn(fedimint_atomic_broadcast::run(
            self.keychains[peer_index].clone(),
            self.databases[peer_index].clone(),
            session_index,
            mempool_item_receiver,
            incoming_receiver,
            outgoing_sender,
            ordered_item_sender,
            self.shutdown_receiver.clone(),
        ));

        (broadcast_handle, decision_handle)
    }
}

#[tokio::test]
async fn crash_recovery() {
    //let subscriber = tracing_subscriber::FmtSubscriber::new();
    //tracing::subscriber::set_global_default(subscriber).unwrap();

    let (shutdown_sender, shutdown_receiver) = watch::channel(None);
    let mut federation = Federation::bootstrap(4, shutdown_receiver);

    for _ in 0..4 {
        // we clear the message queues
        federation.reset_connections();

        let handles = vec![
            federation.start_broadcast(0, 0),
            federation.start_broadcast(1, 0),
            federation.start_broadcast(2, 0),
        ];

        tokio::time::sleep(Duration::from_secs(60)).await;

        for (broadcast_handle, decision_handle) in handles {
            decision_handle.abort();
            assert!(broadcast_handle.await.unwrap() == Shutdown::MidSession(0));
        }
    }

    let handles = vec![
        federation.start_broadcast(0, 0),
        federation.start_broadcast(1, 0),
        federation.start_broadcast(2, 0),
        federation.start_broadcast(3, 0),
    ];

    shutdown_sender
        .send(Some((0, Duration::from_secs(30))))
        .unwrap();

    for (broadcast_handle, ..) in handles {
        assert!(broadcast_handle.await.unwrap() == fedimint_atomic_broadcast::Shutdown::Clean(0));
    }
}

#[tokio::test]
async fn catch_up_via_block_download() {
    //let subscriber = tracing_subscriber::FmtSubscriber::new();
    //tracing::subscriber::set_global_default(subscriber).unwrap();

    let (shutdown_sender, shutdown_receiver) = watch::channel(None);
    let mut federation = Federation::bootstrap(4, shutdown_receiver);

    let handles = vec![
        federation.start_broadcast(0, 0),
        federation.start_broadcast(1, 0),
        federation.start_broadcast(2, 0),
    ];

    shutdown_sender
        .send(Some((0, Duration::from_secs(30))))
        .unwrap();

    for (broadcast_handle, ..) in handles {
        assert!(broadcast_handle.await.unwrap() == fedimint_atomic_broadcast::Shutdown::Clean(0));
    }

    // we clear the message queues
    federation.reset_connections();

    shutdown_sender
        .send(Some((1, Duration::from_secs(30))))
        .unwrap();

    let handles = vec![
        federation.start_broadcast(0, 0),
        federation.start_broadcast(1, 0),
        federation.start_broadcast(2, 0),
        federation.start_broadcast(3, 0),
    ];

    for (broadcast_handle, ..) in handles {
        assert!(broadcast_handle.await.unwrap() == fedimint_atomic_broadcast::Shutdown::Clean(1));
    }
}

#[tokio::test]
async fn shuts_down_on_drop() {
    let keychain = bootstrap_keychains(4).pop().unwrap();
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let (mempool_item_sender, mempool_item_receiver) = async_channel::bounded(32);
    let (incoming_message_sender, incoming_message_receiver) = async_channel::bounded(32);
    let (outgoing_message_sender, outgoing_message_receiver) = async_channel::bounded(32);
    let (ordered_item_sender, ordered_item_receiver) = tokio::sync::mpsc::channel(1);
    let (.., shutdown_receiver) = tokio::sync::watch::channel(None);

    let broadcast_handle = tokio::spawn(fedimint_atomic_broadcast::run(
        keychain,
        db,
        0,
        mempool_item_receiver,
        incoming_message_receiver,
        outgoing_message_sender,
        ordered_item_sender,
        shutdown_receiver,
    ));

    std::mem::drop(mempool_item_sender);
    std::mem::drop(incoming_message_sender);
    std::mem::drop(outgoing_message_receiver);

    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    assert!(!broadcast_handle.is_finished());

    std::mem::drop(ordered_item_receiver);

    assert!(broadcast_handle.await.unwrap() == fedimint_atomic_broadcast::Shutdown::MidSession(0));
}

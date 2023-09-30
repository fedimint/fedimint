use fedimint_core::block::{OrderedItem, SignedBlock};
use fedimint_core::db::Database;
use fedimint_core::task::spawn;
use fedimint_core::PeerId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::keychain::Keychain;
use super::{db, session, Decision, Message, Recipient};

pub struct AtomicBroadcast {
    keychain: Keychain,
    db: Database,
    mempool_item_receiver: async_channel::Receiver<Vec<u8>>,
    outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    network_data_receiver: async_channel::Receiver<Vec<u8>>,
    signed_block_receiver: async_channel::Receiver<SignedBlock>,
    relay_handle: JoinHandle<()>,
}

impl AtomicBroadcast {
    /// This function starts the atomic broadcast instance. A running instance
    /// serves signed blocks to peers on request even if we do not run a
    /// session.
    pub fn new(
        keychain: Keychain,
        db: Database,
        mempool_item_receiver: async_channel::Receiver<Vec<u8>>,
        incoming_message_receiver: async_channel::Receiver<(Message, PeerId)>,
        outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    ) -> Self {
        let (network_data_sender, network_data_receiver) = async_channel::bounded(256);
        let (signed_block_sender, signed_block_receiver) = async_channel::bounded(16);

        let db_clone = db.clone();
        let sender_clone = outgoing_message_sender.clone();

        let relay_handle = spawn("atomic relay", async move {
            while let Ok((message, peer_id)) = incoming_message_receiver.recv().await {
                match message {
                    Message::NetworkData(network_data) => {
                        // if we were to await a send the relay loop may get stuck if we are not
                        // running a session
                        network_data_sender.try_send(network_data).ok();
                    }
                    Message::BlockRequest(index) => {
                        if let Some(signed_block) = db::load_block(&db_clone, index).await {
                            sender_clone
                                .send((Message::Block(signed_block), Recipient::Peer(peer_id)))
                                .await
                                .ok();

                            tracing::info!(
                                "Served the block with index {} to peer {}",
                                index,
                                peer_id
                            );
                        }
                    }
                    Message::Block(signed_block) => {
                        // if we were to await a send the relay loop may get stuck if we are not
                        // running a session
                        signed_block_sender.try_send(signed_block).ok();
                    }
                }
            }

            std::future::pending().await
        })
        .expect("some handle on non-wasm");

        Self {
            keychain,
            db,
            mempool_item_receiver,
            outgoing_message_sender,
            network_data_receiver,
            signed_block_receiver,
            relay_handle,
        }
    }

    /// The receiver returns a sequence of items which is a subsequence of
    /// all items ordered in this session and a supersequence of the accepted
    /// items. The end of a session is signaled by the return of Some(None)
    /// while the return of None directly signals that the session has been
    /// interrupted, either by a call to shutdown or by dropping a
    /// decision_sender without sending a decision.
    pub async fn run_session(
        &self,
        index: u64,
    ) -> mpsc::Receiver<Option<(OrderedItem, oneshot::Sender<Decision>)>> {
        let (ordered_item_sender, ordered_item_receiver) = mpsc::channel(256);

        if let Some(signed_block) = db::load_block(&self.db, index).await {
            tracing::info!("Loaded block with index {}", index);

            spawn("atomic run session db", async move {
                let mut decision_receivers = vec![];

                for ordered_item in signed_block.block.items.into_iter() {
                    let (decision_sender, decision_receiver) = oneshot::channel();

                    ordered_item_sender
                        .send(Some((ordered_item, decision_sender)))
                        .await
                        .ok();

                    decision_receivers.push(decision_receiver);
                }

                // signal that the session is complete
                ordered_item_sender.send(None).await.ok();

                for decision_receiver in decision_receivers {
                    // The items in a threshold signed block have to be accepted
                    if let Ok(decision) = decision_receiver.await {
                        assert!(decision == Decision::Accept)
                    }
                }
            });
        } else {
            tracing::info!("Run session with index {}", index);

            let (backup_loader, backup_saver) = db::open_session(self.db.clone(), index).await;

            let keychain = self.keychain.clone();
            let db = self.db.clone();
            let mempool_item_receiver = self.mempool_item_receiver.clone();
            let network_data_receiver = self.network_data_receiver.clone();
            let outgoing_message_sender = self.outgoing_message_sender.clone();
            let signed_block_receiver = self.signed_block_receiver.clone();

            spawn("atomic run session", async move {
                let session_result = session::run(
                    index,
                    keychain,
                    backup_loader,
                    backup_saver,
                    mempool_item_receiver,
                    network_data_receiver,
                    outgoing_message_sender.clone(),
                    ordered_item_sender.clone(),
                    signed_block_receiver,
                );

                if let Ok(signed_block) = session_result.await {
                    tracing::info!("Completed session with index {}", index);

                    db::complete_session(&db, index, signed_block.clone()).await;

                    outgoing_message_sender
                        .send((Message::Block(signed_block), Recipient::Everyone))
                        .await
                        .ok();

                    // signal that the session is complete. It is critical that we do so only after
                    // we call db::complete_session.
                    // Otherwise the broadcast may miss a signed block in its history if Fedimint
                    // Consensus completes the session first and the system
                    // crashes before the signed block is stable on disk.
                    ordered_item_sender.send(None).await.ok();
                } else {
                    tracing::warn!("Session with index {} has been interrupted", index);
                }
            });
        }

        ordered_item_receiver
    }

    /// This function shuts down the serving of blocks and interrupts the
    /// running session.
    pub async fn shutdown(self) {
        self.relay_handle.abort();
        self.relay_handle.await.ok();
    }
}

use fedimint_core::api::WsFederationApi;
use fedimint_core::block::OrderedItem;
use fedimint_core::db::Database;
use fedimint_core::task::spawn;
use tokio::sync::{mpsc, oneshot};

use super::keychain::Keychain;
use super::{db, session, Decision, Message, Recipient};
use crate::LOG_CONSENSUS;

pub struct AtomicBroadcast {
    keychain: Keychain,
    db: Database,
    mempool_item_receiver: async_channel::Receiver<Vec<u8>>,
    incoming_message_receiver: async_channel::Receiver<Message>,
    outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
}

impl AtomicBroadcast {
    /// This function starts the atomic broadcast instance. A running instance
    /// serves signed blocks to peers on request even if we do not run a
    /// session.
    pub fn new(
        keychain: Keychain,
        db: Database,
        mempool_item_receiver: async_channel::Receiver<Vec<u8>>,
        incoming_message_receiver: async_channel::Receiver<Message>,
        outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    ) -> Self {
        Self {
            keychain,
            db,
            mempool_item_receiver,
            incoming_message_receiver,
            outgoing_message_sender,
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
        federation_api: WsFederationApi,
    ) -> mpsc::Receiver<Option<(OrderedItem, oneshot::Sender<Decision>)>> {
        let (ordered_item_sender, ordered_item_receiver) = mpsc::channel(256);

        if let Some(signed_block) = db::load_block(&self.db, index).await {
            tracing::info!(target: LOG_CONSENSUS,"Loaded block with index {}", index);

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
                        assert_eq!(decision, Decision::Accept)
                    }
                }
            });
        } else {
            tracing::info!(target: LOG_CONSENSUS,"Run session with index {}", index);

            let (backup_loader, backup_saver) = db::open_session(self.db.clone(), index).await;

            let keychain = self.keychain.clone();
            let db = self.db.clone();
            let mempool_item_receiver = self.mempool_item_receiver.clone();
            let incoming_message_receiver = self.incoming_message_receiver.clone();
            let outgoing_message_sender = self.outgoing_message_sender.clone();

            spawn("atomic run session", async move {
                let session_result = session::run(
                    index,
                    keychain,
                    backup_loader,
                    backup_saver,
                    mempool_item_receiver,
                    incoming_message_receiver,
                    outgoing_message_sender,
                    ordered_item_sender.clone(),
                    federation_api,
                );

                if let Ok(signed_block) = session_result.await {
                    db::complete_session(&db, index, signed_block.clone()).await;

                    tracing::info!(target: LOG_CONSENSUS,"Completed session with index {}", index);

                    // signal that the session is complete. It is critical that we do so only after
                    // we call db::complete_session.
                    // Otherwise the broadcast may miss a signed block in its history if Fedimint
                    // Consensus signal first and the system
                    // crashes before the signed block is stable on disk.
                    ordered_item_sender.send(None).await.ok();
                } else {
                    tracing::warn!(target: LOG_CONSENSUS,"Session with index {} has been interrupted", index);
                }
            });
        }

        ordered_item_receiver
    }
}

use std::time::Duration;

use fedimint_core::db::Database;
use fedimint_core::PeerId;
use tokio::sync::{mpsc, oneshot, watch};

use crate::keychain::Keychain;
use crate::{
    db, session, AcceptedItem, Decision, Message, OrderedItem, Recipient, Shutdown, SignedBlock,
};

async fn relay_messages(
    db: Database,
    incoming_message_receiver: async_channel::Receiver<(Message, PeerId)>,
    outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    network_data_sender: async_channel::Sender<Vec<u8>>,
    signed_block_sender: async_channel::Sender<SignedBlock>,
) {
    while let Ok((message, peer_id)) = incoming_message_receiver.recv().await {
        match message {
            Message::NetworkData(network_data) => {
                network_data_sender.send(network_data).await.ok();
            }
            Message::BlockRequest(index) => {
                if let Some(signed_block) = db::load_block(&db, index).await {
                    outgoing_message_sender
                        .send((Message::Block(signed_block), Recipient::Peer(peer_id)))
                        .await
                        .ok();

                    tracing::info!("Served the block with index {} to peer {}", index, peer_id);
                }
            }
            Message::Block(signed_block) => {
                signed_block_sender.send(signed_block).await.ok();
            }
        }
    }

    std::future::pending().await
}

async fn process_signed_block(
    signed_block: SignedBlock,
    ordered_item_sender: mpsc::Sender<OrderedItem>,
) -> anyhow::Result<()> {
    for AcceptedItem { item, peer_id } in signed_block.block.items.iter() {
        let (decision_sender, decision_receiver) = oneshot::channel();

        ordered_item_sender.try_send(OrderedItem {
            item: item.clone(),
            block_index: signed_block.block.index,
            peer_id: peer_id.clone(),
            decision_sender,
        })?;

        // The threshold signed blocks items have to be accepted by Fedimint Consensus.
        assert!(decision_receiver.await? == Decision::Accept);
    }
    Ok(())
}

pub async fn run(
    keychain: Keychain,
    db: Database,
    mut index: u64,
    mempool_item_receiver: async_channel::Receiver<Vec<u8>>,
    incoming_message_receiver: async_channel::Receiver<(Message, PeerId)>,
    outgoing_message_sender: async_channel::Sender<(Message, Recipient)>,
    ordered_item_sender: mpsc::Sender<OrderedItem>,
    clean_shutdown_receiver: watch::Receiver<Option<(u64, Duration)>>,
) -> Shutdown {
    let (network_data_sender, network_data_receiver) = async_channel::bounded(256);
    let (signed_block_sender, signed_block_receiver) = async_channel::bounded(16);

    let relay_handle = tokio::spawn(relay_messages(
        db.clone(),
        incoming_message_receiver.clone(),
        outgoing_message_sender.clone(),
        network_data_sender.clone(),
        signed_block_sender.clone(),
    ));

    loop {
        if let Some(signed_block) = db::load_block(&db, index).await {
            tracing::info!("Loaded block with index {}", index);
            if process_signed_block(signed_block, ordered_item_sender.clone())
                .await
                .is_err()
            {
                relay_handle.abort();
                relay_handle.await.ok();

                return Shutdown::MidSession(index);
            }
        } else {
            tracing::info!("Run session with index {}", index);
            let (backup_loader, backup_saver) = db::open_session(db.clone(), index).await;

            let session_result = session::run(
                index,
                keychain.clone(),
                backup_loader,
                backup_saver,
                mempool_item_receiver.clone(),
                network_data_receiver.clone(),
                outgoing_message_sender.clone(),
                ordered_item_sender.clone(),
                signed_block_receiver.clone(),
            );

            match session_result.await {
                Ok(signed_block) => {
                    tracing::info!("Completed session with index {}", index);
                    db::complete_session(&db, index, signed_block.clone()).await;

                    outgoing_message_sender
                        .send((Message::Block(signed_block), Recipient::Everyone))
                        .await
                        .ok();
                }
                Err(..) => {
                    relay_handle.abort();
                    relay_handle.await.ok();

                    return Shutdown::MidSession(index);
                }
            };
        }

        let clean_shutdown = clean_shutdown_receiver.borrow().to_owned();
        if let Some((shutdown_index, shutdown_delay)) = clean_shutdown {
            if index == shutdown_index {
                tracing::info!("Initiate clean shutdown after index {}", index);

                // we delay the shutdown to allow lagging nodes to complete the session as well
                tokio::time::sleep(shutdown_delay).await;

                relay_handle.abort();
                relay_handle.await.ok();

                return Shutdown::Clean(index);
            }
        }

        index += 1;
    }
}

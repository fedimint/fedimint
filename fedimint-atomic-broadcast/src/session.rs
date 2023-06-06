use std::collections::BTreeMap;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use async_channel::{Receiver, Sender};
use fedimint_core::encoding::Encodable;
use tokio::sync::{oneshot, watch};

use crate::{
    conversion::{to_node_index, to_peer_id},
    data_provider::{DataProvider, UnitData},
    db,
    finalization_handler::FinalizationHandler,
    keychain::Keychain,
    network::Network,
    spawner::Spawner,
    AcceptedItem, Block, Decision, Message, OrderedItem, Recipient, SignedBlock,
};

// this function completes a session with the following steps:
// - set up the aleph bft session
// - periodically request the corresponding signed block from peers
// - combine the accepted items into a block until we reach a preset
//   number of ordered batches or a signed block arrives
// - collect signatures until we reach the threshold or a signed block arrives
pub async fn run(
    index: u64,
    keychain: Keychain,
    backup_loader: std::io::Cursor<Vec<u8>>,
    backup_saver: db::UnitSaver,
    item_receiver: Receiver<Vec<u8>>,
    network_data_receiver: Receiver<Vec<u8>>,
    outgoing_message_sender: Sender<(Message, Recipient)>,
    ordered_item_sender: tokio::sync::mpsc::Sender<OrderedItem>,
    signed_block_receiver: Receiver<SignedBlock>,
) -> anyhow::Result<SignedBlock> {
    const MAX_ROUND: u16 = 5000;
    const ROUND_DELAY: f64 = 250.0;
    const EXPONETIAL_SLOWDOWN_OFFSET: usize = 3000;
    const BASE: f64 = 1.01;
    const BLOCK_REQUEST_DELAY: Duration = Duration::from_secs(10);

    let mut config = aleph_bft::default_config(
        keychain.peer_count.into(),
        keychain.peer_id.into(),
        index.into(),
    );

    // In order to bound a sessions RAM consumption we need to bound its number of units
    // and therefore its number of rounds. Since we use a session to create a threshold
    // signature for the corresponding block we have to guarantee that an attacker cannot
    // exhaust our memory by preventing the creation of a threshold signature, thereby
    // keeping the session open indefinitely. Hence we increase the delay between rounds
    // exponentially such that MAX_ROUND would only be reached after roughly 350 years.
    // In case of such an attack the broadcast stops ordering any items until the attack subsides.
    config.max_round = MAX_ROUND;
    config.delay_config.unit_creation_delay = std::sync::Arc::new(|round_index| {
        let delay = if round_index == 0 {
            0.0
        } else if round_index < EXPONETIAL_SLOWDOWN_OFFSET {
            ROUND_DELAY
        } else {
            ROUND_DELAY * BASE.powf((round_index - EXPONETIAL_SLOWDOWN_OFFSET) as f64)
        };

        Duration::from_millis(delay.round() as u64)
    });

    // the number of units ordered in a single aleph session is bounded
    let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
    let (signature_sender, signature_receiver) = watch::channel(None);
    let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

    let aleph_handle = tokio::spawn(aleph_bft::run_session(
        config,
        aleph_bft::LocalIO::new(
            DataProvider::new(keychain.clone(), item_receiver, signature_receiver),
            FinalizationHandler::new(unit_data_sender),
            backup_saver,
            backup_loader,
        ),
        Network::new(network_data_receiver, outgoing_message_sender.clone()),
        keychain.clone(),
        Spawner::new(),
        aleph_bft::Terminator::create_root(terminator_receiver, "Terminator"),
    ));

    // we periodically request the signed block corresponding to the current session
    // to recover in case we have been left behind by our peers
    let block_request_handle = tokio::spawn(async move {
        for peer_id in (0..keychain.peer_count)
            .map(|peer_index| to_peer_id(peer_index.into()))
            .cycle()
        {
            if outgoing_message_sender
                .send((Message::BlockRequest(index), Recipient::Peer(peer_id)))
                .await
                .is_err()
            {
                break;
            }

            tokio::time::sleep(BLOCK_REQUEST_DELAY).await;
        }
    });

    // this is the minimum number of unit data that will be ordered before we reach the
    // EXPONETIAL_SLOWDOWN_OFFSET even if no malicious peer attaches unit data
    let n_batches_per_block = EXPONETIAL_SLOWDOWN_OFFSET * keychain.peer_count / 3;
    let mut items = vec![];
    let mut n_batches = 0;

    // we build a block out of the ordered batches until either we have processed
    // n_batches_per_block blocks or a signed block arrives from our peers
    while n_batches < n_batches_per_block {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let UnitData::Batch(batch_items, signature, node_index) = unit_data? {
                    if keychain.verify(&batch_items.consensus_hash(), &signature, node_index){
                        // since the signature is valid the node index can be converted to a peer id
                        let peer_id = to_peer_id(node_index);

                        for item in batch_items {
                            let (decision_sender, decision_receiver) = oneshot::channel();

                            ordered_item_sender.try_send(OrderedItem{
                                item: item.clone(),
                                block_index: index,
                                peer_id,
                                decision_sender
                            })?;

                            // we add the item to the block if and only if they are accepted by Fedimint Consensus
                            if decision_receiver.await? == Decision::Accept {
                                items.push(AcceptedItem{item, peer_id});
                            }
                        }

                        n_batches += 1;
                    }
                }
            },

            signed_block = signed_block_receiver.recv() => {
                let SignedBlock{block, signature} = signed_block?;

                if block.index == index
                    && signature.len() == keychain.threshold
                    && signature.iter().all(|(peer_id, sig)| {
                        keychain.verify(&block.header(), sig, to_node_index(*peer_id))
                }){
                    // The items we have already accepted have to be in the threshold signed block
                    assert!(items.iter().eq(block.items.iter().take(items.len())));

                    // We send the not yet processesed items in the block to Fedimint Consensus
                    for AcceptedItem{item, peer_id} in block.items.iter().skip(items.len()) {
                        let (decision_sender, decision_receiver) = oneshot::channel();

                        ordered_item_sender.try_send(OrderedItem{
                            item: item.clone(),
                            block_index: index,
                            peer_id: peer_id.clone(),
                            decision_sender
                        })?;

                        // The threshold signed blocks items have to be accepted by Fedimint Consensus.
                        assert!(decision_receiver.await? == Decision::Accept);
                    }

                    terminator_sender.send(()).ok();
                    block_request_handle.abort();
                    aleph_handle.await.ok();
                    block_request_handle.await.ok();

                    return Ok(SignedBlock{block, signature});
                }
            }

            _ = ordered_item_sender.closed() => anyhow::bail!("Ordered Item Receiver has been droppped")
        }
    }

    // sign the block and send the signature to the data_provider to order it
    let block = Block { index, items };
    let header = block.header();
    let single_signature = keychain.sign(&header).await;

    signature_sender.send(Some(single_signature))?;

    let mut signature = BTreeMap::new();

    // we collect the ordered signatures until we either obtain a threshold signature
    // or a signed block arrives from our peers
    while signature.len() < keychain.threshold {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let UnitData::Signature(single_signature, node_index) = unit_data? {
                    if keychain.verify(&header, &single_signature, node_index){
                        // since the signature is valid the node index can be converted to a peer id
                        signature.insert(to_peer_id(node_index), single_signature);
                    }
                }
            }

            signed_block = signed_block_receiver.recv() => {
                let SignedBlock{block, signature}  = signed_block?;

                if block.index == index
                    && signature.len() == keychain.threshold
                    && signature.iter().all(|(peer_id, sig)| {
                        keychain.verify(&block.header(), sig, to_node_index(*peer_id))
                }){
                    // We check that the block we have created agrees with the fedarations consensus
                    assert!(header == block.header());

                    terminator_sender.send(()).ok();
                    block_request_handle.abort();
                    aleph_handle.await.ok();
                    block_request_handle.await.ok();

                    return Ok(SignedBlock{block, signature});

                }
            }
        }
    }

    terminator_sender.send(()).ok();
    block_request_handle.abort();
    aleph_handle.await.ok();
    block_request_handle.await.ok();

    return Ok(SignedBlock { block, signature });
}

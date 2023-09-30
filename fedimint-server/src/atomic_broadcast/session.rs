use std::collections::BTreeMap;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use async_channel::{Receiver, Sender};
use bitcoin_hashes_12::Hash;
use fedimint_core::api::{FederationApiExt, WsFederationApi};
use fedimint_core::block::{consensus_hash_sha256, Block, OrderedItem, SignedBlock};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::VerifiableResponse;
use fedimint_core::task::{sleep, spawn};
use tokio::sync::{mpsc, oneshot, watch};

use super::conversion::{to_node_index, to_peer_id};
use super::data_provider::{DataProvider, UnitData};
use super::finalization_handler::FinalizationHandler;
use super::keychain::Keychain;
use super::network::Network;
use super::spawner::Spawner;
use super::{db, Decision, Message, Recipient};
/// this function completes a session with the following steps:
/// - set up the aleph bft session
/// - combine the accepted items into a block until we reach a preset number of
///   ordered batches or a signed block arrives
/// - collect signatures until we reach the threshold or a signed block arrives
#[allow(clippy::too_many_arguments)]
pub async fn run(
    session_index: u64,
    keychain: Keychain,
    backup_loader: std::io::Cursor<Vec<u8>>,
    backup_saver: db::UnitSaver,
    item_receiver: Receiver<Vec<u8>>,
    incoming_message_receiver: Receiver<Message>,
    outgoing_message_sender: Sender<(Message, Recipient)>,
    ordered_item_sender: mpsc::Sender<Option<(OrderedItem, oneshot::Sender<Decision>)>>,
    federation_api: WsFederationApi,
) -> anyhow::Result<SignedBlock> {
    const MAX_ROUND: u16 = 5000;
    const ROUND_DELAY: f64 = 250.0;
    const EXPONENTIAL_SLOWDOWN_OFFSET: usize = 3000;
    const BASE: f64 = 1.01;

    let mut config = aleph_bft::default_config(
        keychain.peer_count().into(),
        keychain.peer_id().to_usize().into(),
        session_index,
    );

    // In order to bound a sessions RAM consumption we need to bound its number of
    // units and therefore its number of rounds. Since we use a session to
    // create a threshold signature for the corresponding block we have to
    // guarantee that an attacker cannot exhaust our memory by preventing the
    // creation of a threshold signature, thereby keeping the session open
    // indefinitely. Hence we increase the delay between rounds exponentially
    // such that MAX_ROUND would only be reached after roughly 350 years.
    // In case of such an attack the broadcast stops ordering any items until the
    // attack subsides.
    config.max_round = MAX_ROUND;
    config.delay_config.unit_creation_delay = std::sync::Arc::new(|round_index| {
        let delay = if round_index == 0 {
            0.0
        } else {
            ROUND_DELAY * BASE.powf(round_index.saturating_sub(EXPONENTIAL_SLOWDOWN_OFFSET) as f64)
        };

        Duration::from_millis(delay.round() as u64)
    });

    // the number of units ordered in a single aleph session is bounded
    let (unit_data_sender, unit_data_receiver) = async_channel::unbounded();
    let (signature_sender, signature_receiver) = watch::channel(None);
    let (terminator_sender, terminator_receiver) = futures::channel::oneshot::channel();

    let aleph_handle = spawn(
        "aleph run session",
        aleph_bft::run_session(
            config,
            aleph_bft::LocalIO::new(
                DataProvider::new(keychain.clone(), item_receiver, signature_receiver),
                FinalizationHandler::new(unit_data_sender),
                backup_saver,
                backup_loader,
            ),
            Network::new(incoming_message_receiver, outgoing_message_sender.clone()),
            keychain.clone(),
            Spawner::new(),
            aleph_bft::Terminator::create_root(terminator_receiver, "Terminator"),
        ),
    )
    .expect("some handle on non-wasm");

    // this is the minimum number of unit data that will be ordered before we reach
    // the EXPONENTIAL_SLOWDOWN_OFFSET even if no malicious peer attaches unit
    // data
    let batches_per_block = EXPONENTIAL_SLOWDOWN_OFFSET * keychain.peer_count() / 3;
    let mut num_batches = 0;
    let mut pending_items = vec![];

    // we build a block out of the ordered batches until either we have processed
    // n_batches_per_block blocks or a signed block arrives from our peers
    while num_batches < batches_per_block {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let UnitData::Batch(items, signature, node_index) = unit_data? {
                    let hash = consensus_hash_sha256(&items);
                    if keychain.verify(hash.as_byte_array(), &signature, node_index){
                        // since the signature is valid the node index can be converted to a peer id
                        let peer_id = to_peer_id(node_index);

                        for item in items {
                            let ordered_item = OrderedItem {
                                item,
                                index: pending_items.len() as u64,
                                peer_id
                            };

                            let (decision_sender, decision_receiver) = oneshot::channel();

                            ordered_item_sender.send(Some((
                                ordered_item.clone(),
                                decision_sender
                            ))).await?;

                            pending_items.push((ordered_item, decision_receiver));
                        }

                        num_batches += 1;
                    }
                }
            },
            signed_block = request_signed_block(session_index, keychain.clone(), &federation_api) => {
                let mut accepted_items = vec![];
                for (ordered_item, decision_receiver) in pending_items{
                    // we add the item to the block if and only if it is accepted by Fedimint Consensus
                    if decision_receiver.await? == Decision::Accept {
                        accepted_items.push(ordered_item);
                    }
                }

                // The items we have already accepted have to be in the threshold signed block
                assert!(accepted_items.iter().eq(signed_block.block.items.iter().take(accepted_items.len())));

                // We send the not yet processed items in the block to Fedimint Consensus
                let mut decision_receivers = vec![];
                for ordered_item in signed_block.block.items.iter().skip(accepted_items.len()) {
                    let (decision_sender, decision_receiver) = oneshot::channel();

                    ordered_item_sender.send(Some((
                        ordered_item.clone(),
                        decision_sender
                    ))).await?;

                    decision_receivers.push(decision_receiver);
                }

                for decision_receiver in decision_receivers {
                    // The threshold signed blocks items have to be accepted by Fedimint Consensus.
                    assert!(decision_receiver.await? == Decision::Accept);
                }

                terminator_sender.send(()).ok();
                aleph_handle.await.ok();

                return Ok(signed_block);
            }

            _ = ordered_item_sender.closed() => anyhow::bail!("Ordered Item Receiver has been dropped")
        }
    }

    let mut accepted_items = vec![];
    for (ordered_item, decision_receiver) in pending_items {
        // we add the item to the block if and only if it is accepted by Fedimint
        // Consensus
        if decision_receiver.await? == Decision::Accept {
            accepted_items.push(ordered_item);
        }
    }

    // sign the block and send the signature to the data_provider to order it
    let block = Block {
        index: session_index,
        items: accepted_items,
    };
    let header = block.header();

    // we send our own signature to the data provider to be broadcasted
    signature_sender.send(Some(keychain.sign(&header).await))?;

    let mut signatures = BTreeMap::new();

    // we collect the ordered signatures until we either obtain a threshold
    // signature or a signed block arrives from our peers
    while signatures.len() < keychain.threshold() {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let UnitData::Signature(signature, node_index) = unit_data? {
                    if keychain.verify(&header, &signature, node_index){
                        // since the signature is valid the node index can be converted to a peer id
                        signatures.insert(to_peer_id(node_index), signature);
                    }
                }
            }

            signed_block = request_signed_block(session_index, keychain.clone(), &federation_api) => {
                // We check that the block we have created agrees with the federations consensus
                assert!(header == signed_block.block.header());

                terminator_sender.send(()).ok();
                aleph_handle.await.ok();

                return Ok(signed_block);
            }
        }
    }

    terminator_sender.send(()).ok();
    aleph_handle.await.ok();

    Ok(SignedBlock { block, signatures })
}

async fn request_signed_block(
    index: u64,
    keychain: Keychain,
    federation_api: &WsFederationApi,
) -> SignedBlock {
    // we wait until we have stalled
    sleep(Duration::from_secs(5)).await;

    let total_peers = keychain.peer_count();

    let verifier = move |signed_block: &SignedBlock| {
        signed_block.block.index == index
            && signed_block.signatures.len() == keychain.threshold()
            && signed_block.signatures.iter().all(|(peer_id, sig)| {
                keychain.verify(&signed_block.block.header(), sig, to_node_index(*peer_id))
            })
    };

    loop {
        let result = federation_api
            .request_with_strategy(
                VerifiableResponse::new(verifier.clone(), false, total_peers),
                "get_block".to_string(),
                ApiRequestErased::new(index),
            )
            .await;
        match result {
            Ok(signed_block) => return signed_block,
            Err(error) => tracing::error!("Error while requesting signed block: {}", error),
        }
    }
}

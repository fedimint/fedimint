use std::collections::BTreeMap;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use async_channel::Receiver;
use bitcoin_hashes_12::Hash;
use fedimint_core::api::{FederationApiExt, WsFederationApi};
use fedimint_core::block::{consensus_hash_sha256, SchnorrSignature, SignedBlock};
use fedimint_core::endpoint_constants::AWAIT_SIGNED_BLOCK_ENDPOINT;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::query::VerifiableResponse;
use fedimint_core::task::sleep;
use tokio::sync::watch;

use super::conversion::{to_node_index, to_peer_id};
use super::data_provider::UnitData;
use super::keychain::Keychain;
use crate::consensus::FedimintConsensus;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut consensus: FedimintConsensus,
    batches_per_block: usize,
    unit_data_receiver: Receiver<UnitData>,
    signature_sender: watch::Sender<Option<SchnorrSignature>>,
    keychain: Keychain,
    federation_api: WsFederationApi,
) -> anyhow::Result<()> {
    let mut num_batches = 0;

    // we build a block out of the ordered batches until either we have processed
    // n_batches_per_block blocks or a signed block arrives from our peers
    while num_batches < batches_per_block {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let UnitData::Batch(items, signature, node_index) = unit_data? {
                    let hash = consensus_hash_sha256(&items);
                    if keychain.verify(hash.as_byte_array(), &signature, node_index){
                        for item in items {
                            // since the signature is valid the node index can be converted to a peer id
                            consensus.process_consensus_item(item.clone(), to_peer_id(node_index)).await.ok();
                        }

                        num_batches += 1;
                    }
                }
            },
            signed_block = request_signed_block(consensus.session_index, keychain.clone(), &federation_api) => {
                let partial_block = consensus.build_block().await.items;

                assert!(partial_block.len() <= signed_block.block.items.len());

                assert!(signed_block.block.items.iter().take(partial_block.len()).eq(partial_block.iter()));

                for accepted_item in signed_block.block.items.clone() {
                    assert!(consensus.process_consensus_item(accepted_item.item, accepted_item.peer).await.is_ok());
                }

                consensus.complete_session(signed_block).await;

                return Ok(());
            }
        }
    }

    let block = consensus.build_block().await;
    let header = block.header(consensus.session_index);

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
            signed_block = request_signed_block(consensus.session_index, keychain.clone(), &federation_api) => {
                // We check that the block we have created agrees with the federations consensus
                assert!(header == signed_block.block.header(consensus.session_index));

                consensus.complete_session(signed_block).await;

                return Ok(());
            }
        }
    }

    consensus
        .complete_session(SignedBlock { block, signatures })
        .await;

    Ok(())
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
        signed_block.signatures.len() == keychain.threshold()
            && signed_block.signatures.iter().all(|(peer_id, sig)| {
                keychain.verify(
                    &signed_block.block.header(index),
                    sig,
                    to_node_index(*peer_id),
                )
            })
    };

    loop {
        let result = federation_api
            .request_with_strategy(
                VerifiableResponse::new(verifier.clone(), false, total_peers),
                AWAIT_SIGNED_BLOCK_ENDPOINT.to_string(),
                ApiRequestErased::new(index),
            )
            .await;

        match result {
            Ok(signed_block) => return signed_block,
            Err(error) => tracing::error!("Error while requesting signed block: {}", error),
        }
    }
}

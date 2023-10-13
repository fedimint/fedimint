use std::collections::BTreeMap;
use std::time::Duration;

use aleph_bft::Keychain as KeychainTrait;
use anyhow::anyhow;
use async_channel::Receiver;
use fedimint_core::api::{FederationApiExt, WsFederationApi};
use fedimint_core::block::{SchnorrSignature, SignedBlock};
use fedimint_core::encoding::Decodable;
use fedimint_core::endpoint_constants::AWAIT_SIGNED_BLOCK_ENDPOINT;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiRequestErased, SerdeModuleEncoding};
use fedimint_core::query::FilterMap;
use fedimint_core::task::sleep;
use fedimint_core::PeerId;
use tokio::sync::watch;

use super::conversion::to_node_index;
use super::data_provider::UnitData;
use super::keychain::Keychain;
use crate::consensus::FedimintConsensus;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut consensus: FedimintConsensus,
    batches_per_block: usize,
    unit_data_receiver: Receiver<(UnitData, PeerId)>,
    signature_sender: watch::Sender<Option<SchnorrSignature>>,
    keychain: Keychain,
    federation_api: WsFederationApi,
) -> anyhow::Result<(FedimintConsensus, SignedBlock)> {
    let mut num_batches = 0;

    // we build a block out of the ordered batches until either we have processed
    // n_batches_per_block blocks or a signed block arrives from our peers
    while num_batches < batches_per_block {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let (UnitData::Batch(bytes), peer) = unit_data? {
                    if let Ok(items) = Vec::<ConsensusItem>::consensus_decode(&mut bytes.as_slice(), &consensus.decoders()){
                        for item in items {
                            // since the signature is valid the node index can be converted to a peer id
                            consensus.process_consensus_item(item.clone(), peer).await.ok();
                        }
                    }
                    num_batches += 1;
                }
            },
            signed_block = request_signed_block(
                consensus.session_index,
                keychain.clone(),
                consensus.decoders(),
                &federation_api)
            => {
                let partial_block = consensus.build_block().await.items;

                assert!(partial_block.len() <= signed_block.block.items.len());

                assert!(signed_block.block.items.iter().take(partial_block.len()).eq(partial_block.iter()));

                for accepted_item in signed_block.block.items.clone() {
                    assert!(consensus.process_consensus_item(accepted_item.item, accepted_item.peer).await.is_ok());
                }

                return Ok((consensus, signed_block));
            }
        }
    }

    let block = consensus.build_block().await;
    let header = block.header(consensus.session_index);

    // we send our own signature to the data provider to be broadcasted
    signature_sender.send(Some(keychain.sign(&header)))?;

    let mut signatures = BTreeMap::new();

    // we collect the ordered signatures until we either obtain a threshold
    // signature or a signed block arrives from our peers
    while signatures.len() < keychain.threshold() {
        tokio::select! {
            unit_data = unit_data_receiver.recv() => {
                if let (UnitData::Signature(signature), peer) = unit_data? {
                    if keychain.verify(&header, &signature, to_node_index(peer)){
                        // since the signature is valid the node index can be converted to a peer id
                        signatures.insert(peer, signature);
                    }
                }
            }
            signed_block = request_signed_block(
                consensus.session_index,
                keychain.clone(),
                consensus.decoders(),
                &federation_api
            ) => {
                // We check that the block we have created agrees with the federations consensus
                assert!(header == signed_block.block.header(consensus.session_index));

                return Ok((consensus, signed_block));
            }
        }
    }

    Ok((consensus, SignedBlock { block, signatures }))
}

async fn request_signed_block(
    index: u64,
    keychain: Keychain,
    decoders: ModuleDecoderRegistry,
    federation_api: &WsFederationApi,
) -> SignedBlock {
    let total_peers = keychain.peer_count();
    let decoder_clone = decoders.clone();

    let filter_map = move |response: SerdeModuleEncoding<SignedBlock>| match response
        .try_into_inner(&decoder_clone)
    {
        Ok(signed_block) => {
            match signed_block.signatures.len() == keychain.threshold()
                && signed_block.signatures.iter().all(|(peer_id, sig)| {
                    keychain.verify(
                        &signed_block.block.header(index),
                        sig,
                        to_node_index(*peer_id),
                    )
                }) {
                true => Ok(signed_block),
                false => Err(anyhow!("Invalid signatures")),
            }
        }
        Err(error) => Err(anyhow!(error.to_string())),
    };

    loop {
        // we wait until we have stalled
        sleep(Duration::from_secs(5)).await;

        let result = federation_api
            .request_with_strategy(
                FilterMap::new(filter_map.clone(), total_peers),
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

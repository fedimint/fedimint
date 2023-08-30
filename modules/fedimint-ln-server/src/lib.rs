use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{bail, Context};
use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, ModuleDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiEndpointContext, ConsensusProposal, CoreConsensusVersion,
    ExtendsCommonModuleGen, InputMeta, IntoModuleError, ModuleConsensusVersion, ModuleError,
    PeerHandle, ServerModuleGen, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, Amount, NumPeers, OutPoint, PeerId,
    ServerModule,
};
pub use fedimint_ln_common as common;
use fedimint_ln_common::config::{
    FeeConsensus, LightningClientConfig, LightningConfig, LightningConfigConsensus,
    LightningConfigLocal, LightningConfigPrivate, LightningGenParams,
};
use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
use fedimint_ln_common::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, EncryptedPreimage, FundedContract,
    IdentifiableContract, Preimage, PreimageDecryptionShare,
};
use fedimint_ln_common::db::{
    AgreedDecryptionShareContractIdPrefix, AgreedDecryptionShareKey,
    AgreedDecryptionShareKeyPrefix, BlockCountVoteKey, BlockCountVotePrefix, ContractKey,
    ContractKeyPrefix, ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix,
    EncryptedPreimageIndexKey, EncryptedPreimageIndexKeyPrefix, LightningGatewayKey,
    LightningGatewayKeyPrefix, OfferKey, OfferKeyPrefix, ProposeDecryptionShareKey,
    ProposeDecryptionShareKeyPrefix,
};
use fedimint_ln_common::{
    ContractAccount, LightningCommonGen, LightningConsensusItem, LightningError, LightningGateway,
    LightningInput, LightningModuleTypes, LightningOutput, LightningOutputOutcome,
};
use fedimint_metrics::{
    histogram_opts, lazy_static, opts, prometheus, register_histogram, register_int_counter,
    Histogram, IntCounter,
};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::{debug, error, info_span, trace};

lazy_static! {
    pub static ref LN_INCOMING_OFFER: IntCounter = register_int_counter!(opts!(
        "ln_incoming_offer",
        "contracts::IncomingContractOffer"
    ))
    .unwrap();
    pub static ref LN_OUTPUT_OUTCOME_CANCEL_OUTGOING_CONTRACT: IntCounter =
        register_int_counter!(opts!(
            "ln_output_outcome_cancel_outgoing_contract",
            "LightningOutputOutcome::CancelOutgoingContract"
        ))
        .unwrap();
    pub static ref LN_FUNDED_CONTRACT_INCOMING: IntCounter = register_int_counter!(opts!(
        "ln_funded_contract_incoming",
        "contracts::FundedContract::Incoming"
    ))
    .unwrap();
    pub static ref LN_FUNDED_CONTRACT_OUTGOING: IntCounter = register_int_counter!(opts!(
        "ln_funded_contract_outgoing",
        "contracts::FundedContract::Outgoing"
    ))
    .unwrap();
    pub static ref AMOUNTS_BUCKETS_SATS: Vec<f64> = vec![0.0, 0.5, 1.0, 1000.0];
    pub static ref LN_FUNDED_CONTRACT_INCOMING_ACCOUNT_AMOUNTS_SATS: Histogram =
        register_histogram!(histogram_opts!(
            "ln_funded_contract_incoming_account_amounts_sats",
            "contracts::FundedContract::Incoming account amount in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ))
        .unwrap();
    pub static ref LN_FUNDED_CONTRACT_OUTGOING_ACCOUNT_AMOUNTS_SATS: Histogram =
        register_histogram!(histogram_opts!(
            "ln_funded_contract_outgoing_account_amounts_sats",
            "contracts::FundedContract::Outgoing account amounts in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ))
        .unwrap();
    pub static ref ALL_METRICS: [Box<dyn prometheus::core::Collector>; 6] = [
        Box::new(LN_INCOMING_OFFER.clone()),
        Box::new(LN_OUTPUT_OUTCOME_CANCEL_OUTGOING_CONTRACT.clone()),
        Box::new(LN_FUNDED_CONTRACT_INCOMING.clone()),
        Box::new(LN_FUNDED_CONTRACT_OUTGOING.clone()),
        Box::new(LN_FUNDED_CONTRACT_INCOMING_ACCOUNT_AMOUNTS_SATS.clone()),
        Box::new(LN_FUNDED_CONTRACT_OUTGOING_ACCOUNT_AMOUNTS_SATS.clone()),
    ];
}

#[derive(Debug, Clone)]
pub struct LightningGen;

impl ExtendsCommonModuleGen for LightningGen {
    type Common = LightningCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleGen for LightningGen {
    type Params = LightningGenParams;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(0, 0, &[(0, 0)])
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        // Ensure all metrics are initialized
        for metric in ALL_METRICS.iter() {
            metric.collect();
        }
        Ok(Lightning::new(cfg.to_typed()?, task_group)?.into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let sks = threshold_crypto::SecretKeySet::random(peers.degree(), &mut OsRng);
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningConfig {
                        local: LightningConfigLocal {
                            bitcoin_rpc: params.local.bitcoin_rpc.clone(),
                        },
                        consensus: LightningConfigConsensus {
                            threshold_pub_keys: pks.clone(),
                            fee_consensus: FeeConsensus::default(),
                            network: params.consensus.network,
                        },
                        private: LightningConfigPrivate {
                            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        },
                    }
                    .to_erased(),
                )
            })
            .collect();

        server_cfg
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let g1 = peers.run_dkg_g1(()).await?;

        let keys = g1[&()].threshold_crypto();

        let server = LightningConfig {
            local: LightningConfigLocal {
                bitcoin_rpc: params.local.bitcoin_rpc.clone(),
            },
            consensus: LightningConfigConsensus {
                threshold_pub_keys: keys.public_key_set,
                fee_consensus: Default::default(),
                network: params.consensus.network,
            },
            private: LightningConfigPrivate {
                threshold_sec_key: keys.secret_key_share,
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<LightningConfig>()?;
        if config.private.threshold_sec_key.public_key_share()
            != config
                .consensus
                .threshold_pub_keys
                .public_key_share(identity.to_usize())
        {
            bail!("Lightning private key doesn't match pubkey share");
        }
        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<LightningClientConfig> {
        let config = LightningConfigConsensus::from_erased(config)?;
        Ok(LightningClientConfig {
            threshold_pub_key: config.threshold_pub_keys.public_key(),
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut lightning: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::AgreedDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        AgreedDecryptionShareKeyPrefix,
                        AgreedDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Accepted Decryption Shares"
                    );
                }
                DbKeyPrefix::Contract => {
                    push_db_pair_items!(
                        dbtx,
                        ContractKeyPrefix,
                        ContractKey,
                        ContractAccount,
                        lightning,
                        "Contracts"
                    );
                }
                DbKeyPrefix::ContractUpdate => {
                    push_db_pair_items!(
                        dbtx,
                        ContractUpdateKeyPrefix,
                        ContractUpdateKey,
                        LightningOutputOutcome,
                        lightning,
                        "Contract Updates"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGateway,
                        lightning,
                        "Lightning Gateways"
                    );
                }
                DbKeyPrefix::Offer => {
                    push_db_pair_items!(
                        dbtx,
                        OfferKeyPrefix,
                        OfferKey,
                        IncomingContractOffer,
                        lightning,
                        "Offers"
                    );
                }
                DbKeyPrefix::ProposeDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        ProposeDecryptionShareKeyPrefix,
                        ProposeDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Proposed Decryption Shares"
                    );
                }
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        lightning,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::EncryptedPreimageIndex => {
                    push_db_pair_items!(
                        dbtx,
                        EncryptedPreimageIndexKeyPrefix,
                        EncryptedPreimageIndexKey,
                        (),
                        lightning,
                        "Encrypted Preimage Hashes"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}
/// The lightning module implements an account system. It does not have the
/// privacy guarantees of the e-cash mint module but instead allows for smart
/// contracting. There exist three contract types that can be used to "lock"
/// accounts:
///
///   * [Outgoing]: an account locked with an HTLC-like contract allowing to
///     incentivize an external Lightning node to make payments for the funder
///   * [Incoming]: a contract type that represents the acquisition of a
///     preimage belonging to a hash. Every incoming contract is preceded by an
///     offer that specifies how much the seller is asking for the preimage to a
///     particular hash. It also contains some threshold-encrypted data. Once
///     the contract is funded the data is decrypted. If it is a valid preimage
///     the contract's funds are now accessible to the creator of the offer, if
///     not they are accessible to the funder.
///
/// These three primitives allow to integrate the federation with the wider
/// Lightning network through a centralized but untrusted (except for
/// availability) Lightning gateway server.
///
/// [Outgoing]: fedimint_ln_common::contracts::outgoing::OutgoingContract
/// [Incoming]: fedimint_ln_common::contracts::incoming::IncomingContract
#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
    btc_rpc: DynBitcoindRpc,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Gen = LightningGen;
    type VerificationCache = LightningVerificationCache;

    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>) {
        while !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            sleep(Duration::from_millis(1000)).await;
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<LightningConsensusItem> {
        let mut items: Vec<LightningConsensusItem> = dbtx
            .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
            .await
            .map(|(ProposeDecryptionShareKey(contract_id), share)| {
                LightningConsensusItem::DecryptPreimage(contract_id, share)
            })
            .collect()
            .await;

        let block_count_vote = self.block_count().await;

        if block_count_vote != self.consensus_block_count(dbtx).await {
            items.push(LightningConsensusItem::BlockCount(block_count_vote));
        }

        ConsensusProposal::new_auto_trigger(items)
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_item: LightningConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let span = info_span!("process decryption share", %peer_id);
        let _guard = span.enter();

        match consensus_item {
            LightningConsensusItem::DecryptPreimage(contract_id, share) => {
                if dbtx
                    .get_value(&AgreedDecryptionShareKey(contract_id, peer_id))
                    .await
                    .is_some()
                {
                    bail!("Already received a valid decryption share for this peer");
                }

                let account = dbtx
                    .get_value(&ContractKey(contract_id))
                    .await
                    .context("Contract account for this decryption share does not exist")?;

                let (contract, out_point) = match account.contract {
                    FundedContract::Incoming(contract) => (contract.contract, contract.out_point),
                    FundedContract::Outgoing(..) => {
                        bail!("Contract account for this decryption share is outgoing");
                    }
                };

                if contract.decrypted_preimage != DecryptedPreimage::Pending {
                    bail!("Contract for this decryption share is not pending");
                }

                if !self.validate_decryption_share(peer_id, &share, &contract.encrypted_preimage) {
                    bail!("Decryption share is invalid");
                }

                // we save the first ordered valid decryption share for every peer
                dbtx.insert_new_entry(&AgreedDecryptionShareKey(contract_id, peer_id), &share)
                    .await;

                // collect all valid decryption shares previously received for this contract
                let decryption_shares = dbtx
                    .find_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await
                    .map(|(key, decryption_share)| (key.1, decryption_share))
                    .collect::<Vec<_>>()
                    .await;

                if decryption_shares.len() < self.cfg.consensus.threshold() {
                    return Ok(());
                }

                debug!("Beginning to decrypt preimage");

                let preimage_vec = match self.cfg.consensus.threshold_pub_keys.decrypt(
                    decryption_shares
                        .iter()
                        .map(|(peer, share)| (peer.to_usize(), &share.0)),
                    &contract.encrypted_preimage.0,
                ) {
                    Ok(preimage_vec) => preimage_vec,
                    Err(_) => {
                        // TODO: check if that can happen even though shares are verified
                        // before
                        error!(contract_hash = %contract.hash, "Failed to decrypt preimage");
                        return Ok(());
                    }
                };

                // Delete decryption shares once we've decrypted the preimage
                dbtx.remove_entry(&ProposeDecryptionShareKey(contract_id))
                    .await;

                dbtx.remove_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await;

                let decrypted_preimage = if preimage_vec.len() == 32
                    && contract.hash == bitcoin_hashes::sha256::Hash::hash(&preimage_vec)
                {
                    let preimage = Preimage(
                        preimage_vec
                            .as_slice()
                            .try_into()
                            .expect("Invalid preimage length"),
                    );
                    if preimage.to_public_key().is_ok() {
                        DecryptedPreimage::Some(preimage)
                    } else {
                        DecryptedPreimage::Invalid
                    }
                } else {
                    DecryptedPreimage::Invalid
                };

                debug!(?decrypted_preimage);

                // TODO: maybe define update helper fn
                // Update contract
                let contract_db_key = ContractKey(contract_id);
                let mut contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .expect("checked before that it exists");
                let incoming = match &mut contract_account.contract {
                    FundedContract::Incoming(incoming) => incoming,
                    _ => unreachable!("previously checked that it's an incoming contract"),
                };
                incoming.contract.decrypted_preimage = decrypted_preimage.clone();
                trace!(?contract_account, "Updating contract account");
                dbtx.insert_entry(&contract_db_key, &contract_account).await;

                // Update output outcome
                let mut outcome = dbtx
                    .get_value(&ContractUpdateKey(out_point))
                    .await
                    .expect("outcome was created on funding");
                let incoming_contract_outcome_preimage = match &mut outcome {
                    LightningOutputOutcome::Contract {
                        outcome: ContractOutcome::Incoming(decryption_outcome),
                        ..
                    } => decryption_outcome,
                    _ => panic!("We are expeccting an incoming contract"),
                };
                *incoming_contract_outcome_preimage = decrypted_preimage.clone();
                dbtx.insert_entry(&ContractUpdateKey(out_point), &outcome)
                    .await;
            }
            LightningConsensusItem::BlockCount(block_count) => {
                let current_vote = dbtx
                    .get_value(&BlockCountVoteKey(peer_id))
                    .await
                    .unwrap_or(0);

                if block_count < current_vote {
                    bail!("Block count vote decreased");
                }

                if block_count == current_vote {
                    bail!("Block height vote is redundant");
                }

                dbtx.insert_entry(&BlockCountVoteKey(peer_id), &block_count)
                    .await;
            }
        }

        Ok(())
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a LightningInput>,
    ) -> Self::VerificationCache {
        LightningVerificationCache
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b LightningInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let mut account = dbtx
            .get_value(&ContractKey(input.contract_id))
            .await
            .ok_or(LightningError::UnknownContract(input.contract_id))
            .into_module_error_other()?;

        if account.amount < input.amount {
            return Err(LightningError::InsufficientFunds(
                account.amount,
                input.amount,
            ))
            .into_module_error_other();
        }

        let consensus_block_count = self.consensus_block_count(dbtx).await;

        let pub_key = match &account.contract {
            FundedContract::Outgoing(outgoing) => {
                if outgoing.timelock as u64 + 1 > consensus_block_count && !outgoing.cancelled {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningError::MissingPreimage)
                            .into_module_error_other()?
                            .0,
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningError::InvalidPreimage).into_module_error_other();
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Incoming(incoming) => match &incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningError::ContractNotReady).into_module_error_other();
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => match preimage.to_public_key() {
                    Ok(pub_key) => pub_key,
                    Err(_) => {
                        return Err(LightningError::InvalidPreimage).into_module_error_other()
                    }
                },
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        account.amount -= input.amount;

        dbtx.insert_entry(&ContractKey(input.contract_id), &account)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.fee_consensus.contract_input,
            },
            pub_keys: vec![pub_key],
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        match output {
            LightningOutput::Contract(contract) => {
                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .ok_or(LightningError::NoOffer(incoming.hash))
                        .into_module_error_other()?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ))
                        .into_module_error_other();
                    }
                }

                if contract.amount == Amount::ZERO {
                    return Err(LightningError::ZeroOutput).into_module_error_other();
                }

                let contract_db_key = ContractKey(contract.contract.contract_id());

                let updated_contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .map(|mut value: ContractAccount| {
                        value.amount += contract.amount;
                        value
                    })
                    .unwrap_or_else(|| ContractAccount {
                        amount: contract.amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    });

                if dbtx
                    .insert_entry(&contract_db_key, &updated_contract_account)
                    .await
                    .is_none()
                {
                    match &updated_contract_account.contract {
                        FundedContract::Incoming(_) => {
                            LN_FUNDED_CONTRACT_INCOMING_ACCOUNT_AMOUNTS_SATS
                                .observe(updated_contract_account.amount.msats as f64 / 1000.0);
                            LN_FUNDED_CONTRACT_INCOMING.inc();
                        }
                        FundedContract::Outgoing(_) => {
                            LN_FUNDED_CONTRACT_OUTGOING_ACCOUNT_AMOUNTS_SATS
                                .observe(updated_contract_account.amount.msats as f64 / 1000.0);
                            LN_FUNDED_CONTRACT_OUTGOING.inc();
                        }
                    }
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Contract {
                        id: contract.contract.contract_id(),
                        outcome: contract.contract.to_outcome(),
                    },
                )
                .await;

                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .expect("offer exists if output is valid");

                    let decryption_share = self
                        .cfg
                        .private
                        .threshold_sec_key
                        .decrypt_share(&incoming.encrypted_preimage.0)
                        .expect("We checked for decryption share validity on contract creation");

                    dbtx.insert_new_entry(
                        &ProposeDecryptionShareKey(contract.contract.contract_id()),
                        &PreimageDecryptionShare(decryption_share),
                    )
                    .await;

                    dbtx.remove_entry(&OfferKey(offer.hash)).await;
                }

                Ok(TransactionItemAmount {
                    amount: contract.amount,
                    fee: self.cfg.consensus.fee_consensus.contract_output,
                })
            }
            LightningOutput::Offer(offer) => {
                if !offer.encrypted_preimage.0.verify() {
                    return Err(LightningError::InvalidEncryptedPreimage).into_module_error_other();
                }

                // Check that each preimage is only offered for sale once, see #1397
                if dbtx
                    .insert_entry(
                        &EncryptedPreimageIndexKey(offer.encrypted_preimage.consensus_hash()),
                        &(),
                    )
                    .await
                    .is_some()
                {
                    return Err(LightningError::DuplicateEncryptedPreimage)
                        .into_module_error_other();
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Offer { id: offer.id() },
                )
                .await;

                // TODO: sanity-check encrypted preimage size
                dbtx.insert_new_entry(&OfferKey(offer.hash), &(*offer).clone())
                    .await;

                LN_INCOMING_OFFER.inc();

                Ok(TransactionItemAmount::ZERO)
            }
            LightningOutput::CancelOutgoing {
                contract,
                gateway_signature,
            } => {
                let contract_account = dbtx
                    .get_value(&ContractKey(*contract))
                    .await
                    .ok_or(LightningError::UnknownContract(*contract))
                    .into_module_error_other()?;

                let outgoing_contract = match &contract_account.contract {
                    FundedContract::Outgoing(contract) => contract,
                    _ => {
                        return Err(LightningError::NotOutgoingContract).into_module_error_other();
                    }
                };

                secp256k1::global::SECP256K1
                    .verify_schnorr(
                        gateway_signature,
                        &outgoing_contract.cancellation_message().into(),
                        &outgoing_contract.gateway_key,
                    )
                    .map_err(|_| LightningError::InvalidCancellationSignature)
                    .into_module_error_other()?;

                let updated_contract_account = {
                    let mut contract_account = dbtx
                        .get_value(&ContractKey(*contract))
                        .await
                        .expect("Contract exists if output is valid");

                    let outgoing_contract = match &mut contract_account.contract {
                        FundedContract::Outgoing(contract) => contract,
                        _ => {
                            panic!("Contract type was checked in validate_output");
                        }
                    };

                    outgoing_contract.cancelled = true;

                    contract_account
                };

                dbtx.insert_entry(&ContractKey(*contract), &updated_contract_account)
                    .await;

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::CancelOutgoingContract { id: *contract },
                )
                .await;

                LN_OUTPUT_OUTCOME_CANCEL_OUTGOING_CONTRACT.inc();

                Ok(TransactionItemAmount::ZERO)
            }
        }
    }

    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&ContractUpdateKey(out_point)).await
    }

    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(dbtx, &ContractKeyPrefix, |_, v| -(v.amount.msats as i64))
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "block_count",
                async |module: &Lightning, context, _v: ()| -> Option<u64> {
                    Ok(Some(module.consensus_block_count(&mut context.dbtx()).await))
                }
            },
            api_endpoint! {
                "account",
                async |module: &Lightning, context, contract_id: ContractId| -> Option<ContractAccount> {
                    Ok(module
                        .get_contract_account(&mut context.dbtx(), contract_id)
                        .await)
                }
            },
            api_endpoint! {
                "wait_account",
                async |module: &Lightning, context, contract_id: ContractId| -> ContractAccount {
                    Ok(module
                        .wait_contract_account(context, contract_id)
                        .await)
                }
            },
            api_endpoint! {
                "offer",
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> Option<IncomingContractOffer> {
                    Ok(module
                        .get_offer(&mut context.dbtx(), payment_hash)
                        .await)
               }
            },
            api_endpoint! {
                "wait_offer",
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    Ok(module
                        .wait_offer(context, payment_hash)
                        .await)
                }
            },
            api_endpoint! {
                "list_gateways",
                async |module: &Lightning, context, _v: ()| -> Vec<LightningGateway> {
                    Ok(module.list_gateways(&mut context.dbtx()).await)
                }
            },
            api_endpoint! {
                "register_gateway",
                async |module: &Lightning, context, gateway: LightningGateway| -> () {
                    module.register_gateway(&mut context.dbtx(), gateway).await;
                    Ok(())
                }
            },
        ]
    }
}

impl Lightning {
    pub fn new(cfg: LightningConfig, task_group: &mut TaskGroup) -> anyhow::Result<Self> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc, task_group.make_handle())?;
        Ok(Lightning { cfg, btc_rpc })
    }

    pub async fn block_count(&self) -> u64 {
        self.btc_rpc
            .get_block_count()
            .await
            .expect("bitcoind rpc failed")
    }

    pub async fn consensus_block_count(&self, dbtx: &mut ModuleDatabaseTransaction<'_>) -> u64 {
        let peer_count = 3 * (self.cfg.consensus.threshold() / 2) + 1;

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|(.., count)| count)
            .collect::<Vec<_>>()
            .await;

        assert!(counts.len() <= peer_count);

        while counts.len() < peer_count {
            counts.push(0);
        }

        counts.sort_unstable();

        counts[peer_count / 2]
    }

    fn validate_decryption_share(
        &self,
        peer: PeerId,
        share: &PreimageDecryptionShare,
        message: &EncryptedPreimage,
    ) -> bool {
        self.cfg
            .consensus
            .threshold_pub_keys
            .public_key_share(peer.to_usize())
            .verify_decryption_share(&share.0, &message.0)
    }

    pub async fn get_offer(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        dbtx.get_value(&OfferKey(payment_hash)).await
    }

    pub async fn wait_offer(
        &self,
        context: &mut ApiEndpointContext<'_>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> IncomingContractOffer {
        let future = context.wait_key_exists(OfferKey(payment_hash));
        future.await
    }

    pub async fn get_offers(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> Vec<IncomingContractOffer> {
        dbtx.find_by_prefix(&OfferKeyPrefix)
            .await
            .map(|(_, value)| value)
            .collect::<Vec<IncomingContractOffer>>()
            .await
    }

    pub async fn get_contract_account(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        contract_id: ContractId,
    ) -> Option<ContractAccount> {
        dbtx.get_value(&ContractKey(contract_id)).await
    }

    pub async fn wait_contract_account(
        &self,
        context: &mut ApiEndpointContext<'_>,
        contract_id: ContractId,
    ) -> ContractAccount {
        // not using a variable here leads to a !Send error
        let future = context.wait_key_exists(ContractKey(contract_id));
        future.await
    }

    pub async fn list_gateways(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> Vec<LightningGateway> {
        let stream = dbtx.find_by_prefix(&LightningGatewayKeyPrefix).await;
        stream
            .filter_map(|(_, gw)| async {
                // FIXME: actually remove from DB
                if gw.valid_until > fedimint_core::time::now() {
                    Some(gw)
                } else {
                    None
                }
            })
            .collect::<Vec<LightningGateway>>()
            .await
    }

    pub async fn register_gateway(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        gateway: LightningGateway,
    ) {
        dbtx.insert_entry(&LightningGatewayKey(gateway.node_pub_key), &gateway)
            .await;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct LightningVerificationCache;

impl fedimint_core::server::VerificationCache for LightningVerificationCache {}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use bitcoin_hashes::Hash as BitcoinHash;
    use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
    use fedimint_core::config::ConfigGenModuleParams;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::encoding::Encodable;
    use fedimint_core::module::ServerModuleGen;
    use fedimint_core::task::TaskGroup;
    use fedimint_core::{Amount, OutPoint, PeerId, ServerModule, TransactionId};
    use fedimint_ln_common::config::{
        LightningClientConfig, LightningConfig, LightningGenParams, LightningGenParamsConsensus,
        LightningGenParamsLocal, Network,
    };
    use fedimint_ln_common::contracts::incoming::IncomingContractOffer;
    use fedimint_ln_common::contracts::EncryptedPreimage;
    use fedimint_ln_common::LightningOutput;

    use crate::{Lightning, LightningGen};

    const MINTS: usize = 4;

    fn build_configs() -> (Vec<LightningConfig>, LightningClientConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let server_cfg = ServerModuleGen::trusted_dealer_gen(
            &LightningGen,
            &peers,
            &ConfigGenModuleParams::from_typed(LightningGenParams {
                local: LightningGenParamsLocal {
                    bitcoin_rpc: BitcoinRpcConfig {
                        kind: "bitcoind".to_string(),
                        url: "http://localhost:18332".parse().unwrap(),
                    },
                },
                consensus: LightningGenParamsConsensus {
                    network: Network::Regtest,
                },
            })
            .expect("valid config params"),
        );

        let client_cfg = ServerModuleGen::get_client_config(
            &LightningGen,
            &server_cfg[&PeerId::from(0)].consensus,
        )
        .unwrap();

        let server_cfg = server_cfg
            .into_values()
            .map(|config| {
                config
                    .to_typed()
                    .expect("Config was just generated by the same configgen")
            })
            .collect::<Vec<LightningConfig>>();

        (server_cfg, client_cfg)
    }

    #[test_log::test(tokio::test)]
    async fn encrypted_preimage_only_usable_once() {
        let (server_cfg, client_cfg) = build_configs();
        let mut tg = TaskGroup::new();
        let server = Lightning::new(server_cfg[0].clone(), &mut tg).unwrap();

        let preimage = [42u8; 32];
        let encrypted_preimage = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt([42; 32]));

        let hash = preimage.consensus_hash();
        let offer = IncomingContractOffer {
            amount: Amount::from_sats(10),
            hash,
            encrypted_preimage: encrypted_preimage.clone(),
            expiry_time: None,
        };
        let output = LightningOutput::Offer(offer);
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };

        let db = Database::new(MemDatabase::new(), Default::default());
        let mut dbtx = db.begin_transaction().await;

        server
            .process_output(&mut dbtx.with_module_prefix(42), &output, out_point)
            .await
            .expect("First time works");

        let hash2 = [21u8, 32].consensus_hash();
        let offer2 = IncomingContractOffer {
            amount: Amount::from_sats(1),
            hash: hash2,
            encrypted_preimage,
            expiry_time: None,
        };
        let output2 = LightningOutput::Offer(offer2);
        let out_point2 = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 1,
        };

        assert_matches!(
            server
                .process_output(&mut dbtx.with_module_prefix(42), &output2, out_point2)
                .await,
            Err(_)
        );
    }
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::str::FromStr;

    use anyhow::{ensure, Context};
    use bitcoin_hashes::Hash;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
    use fedimint_core::db::{apply_migrations, DatabaseTransaction};
    use fedimint_core::encoding::Encodable;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::{CommonModuleGen, DynServerModuleGen};
    use fedimint_core::{OutPoint, ServerModule, TransactionId};
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
    };
    use fedimint_ln_common::contracts::{
        outgoing, ContractId, DecryptedPreimage, EncryptedPreimage, FundedContract, Preimage,
        PreimageDecryptionShare,
    };
    use fedimint_ln_common::db::{
        AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractKeyPrefix,
        ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix, EncryptedPreimageIndexKey,
        EncryptedPreimageIndexKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey,
        OfferKeyPrefix, ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
    };
    use fedimint_ln_common::LightningCommonGen;
    use fedimint_testing::db::{prepare_snapshot, validate_migrations, BYTE_32, BYTE_8, STRING_64};
    use futures::StreamExt;
    use lightning::routing::gossip::RoutingFees;
    use lightning_invoice::Invoice;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use threshold_crypto::G1Projective;
    use url::Url;

    use crate::{
        ContractAccount, Lightning, LightningGateway, LightningGen, LightningOutputOutcome,
    };

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let contract_id = ContractId::from_str(STRING_64).unwrap();
        let amount = fedimint_core::Amount { msats: 1000 };
        let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let incoming_contract = IncomingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(Preimage(BYTE_32), &threshold_key),
            decrypted_preimage: DecryptedPreimage::Some(Preimage(BYTE_32)),
            gateway_key: pk.x_only_public_key().0,
        };
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };
        let incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: incoming_contract,
            out_point,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: incoming_contract,
            },
        )
        .await;
        let invoice = str::parse::<Invoice>("lnbc10u1pjq37rgsp5cry9r0qqdzp0tl0m27jedvxtrazq0v8xh5rfvzuhm7yxydg50m9qpp5r0cjzjzt7pjwae8trp6dtteh6hstdakzv68atpqx0zshaexghpwsdqqcqpjrzjqfzekav6v27ra0lf3geqmg3hj3xvfu652cuyhk8aa7naqdqvwh6x7zagh5qqy3qqqyqqqqqpqqqqqqgq9q9qyysgq6vf5z83a2q2ua9nwanmc7pql26pwt8smt2xzwp7kjd0mgplmy925s5yz6nlfxt99p2dlffw82gw8kte7lv87pcf4nahslg2vyhhkzwqqxuqmgp");
        let outgoing_contract = FundedContract::Outgoing(outgoing::OutgoingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&[0, 2, 3, 4, 5, 6, 7, 8]),
            gateway_key: pk.x_only_public_key().0,
            timelock: 1000000,
            user_key: pk.x_only_public_key().0,
            invoice: invoice.unwrap(),
            cancelled: false,
        });
        dbtx.insert_new_entry(
            &ContractKey(contract_id),
            &ContractAccount {
                amount,
                contract: outgoing_contract,
            },
        )
        .await;

        let incoming_offer = IncomingContractOffer {
            amount: fedimint_core::Amount { msats: 1000 },
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(Preimage(BYTE_32), &threshold_key),
            expiry_time: None,
        };
        dbtx.insert_new_entry(&OfferKey(incoming_offer.hash), &incoming_offer)
            .await;

        let contract_update_key = ContractUpdateKey(OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        });
        let lightning_output_outcome = LightningOutputOutcome::Offer {
            id: OfferId::from_str(STRING_64).unwrap(),
        };
        dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
            .await;

        let preimage_decryption_share = PreimageDecryptionShare(Standard.sample(&mut OsRng));
        dbtx.insert_new_entry(
            &ProposeDecryptionShareKey(contract_id),
            &preimage_decryption_share,
        )
        .await;

        dbtx.insert_new_entry(
            &AgreedDecryptionShareKey(contract_id, 0.into()),
            &preimage_decryption_share,
        )
        .await;

        let gateway = LightningGateway {
            mint_channel_id: 100,
            gateway_redeem_key: pk.x_only_public_key().0,
            node_pub_key: pk,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
            route_hints: vec![],
            valid_until: fedimint_core::time::now(),
            fees: RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            gateway_id: pk,
        };
        dbtx.insert_new_entry(&LightningGatewayKey(pk), &gateway)
            .await;

        dbtx.insert_new_entry(&EncryptedPreimageIndexKey("foobar".consensus_hash()), &())
            .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_migration_snapshots() {
        prepare_snapshot(
            "lightning-v0",
            |dbtx| {
                Box::pin(async move {
                    create_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                LightningCommonGen::KIND,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() -> anyhow::Result<()> {
        validate_migrations(
            "lightning",
            |db| async move {
                let module = DynServerModuleGen::from(LightningGen);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .context("Error applying migrations to temp database")?;

                // Verify that all of the data from the lightning namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::Contract => {
                            let contracts = dbtx
                                .find_by_prefix(&ContractKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_contracts = contracts.len();
                            ensure!(
                                num_contracts > 0,
                                "validate_migrations was not able to read any contracts"
                            );
                        }
                        DbKeyPrefix::AgreedDecryptionShare => {
                            let agreed_decryption_shares = dbtx
                                .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = agreed_decryption_shares.len();
                            ensure!(
                            num_shares > 0,
                            "validate_migrations was not able to read any AgreedDecryptionShares"
                        );
                        }
                        DbKeyPrefix::ContractUpdate => {
                            let contract_updates = dbtx
                                .find_by_prefix(&ContractUpdateKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_updates = contract_updates.len();
                            ensure!(
                                num_updates > 0,
                                "validate_migrations was not able to read any ContractUpdates"
                            );
                        }
                        DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            ensure!(
                                num_gateways > 0,
                                "validate_migrations was not able to read any LightningGateways"
                            );
                        }
                        DbKeyPrefix::Offer => {
                            let offers = dbtx
                                .find_by_prefix(&OfferKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_offers = offers.len();
                            ensure!(
                                num_offers > 0,
                                "validate_migrations was not able to read any Offers"
                            );
                        }
                        DbKeyPrefix::ProposeDecryptionShare => {
                            let proposed_decryption_shares = dbtx
                                .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = proposed_decryption_shares.len();
                            ensure!(
                            num_shares > 0,
                            "validate_migrations was not able to read any ProposeDecryptionShares"
                        );
                        }
                        DbKeyPrefix::BlockCountVote => {}
                        DbKeyPrefix::EncryptedPreimageIndex => {
                            let encrypted_preimage_index = dbtx
                                .find_by_prefix(&EncryptedPreimageIndexKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = encrypted_preimage_index.len();
                            ensure!(
                                num_shares > 0,
                                "validate_migrations was not able to read any EncryptedPreimageIndexKeys"
                            );
                        }
                    }
                }
                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_LN,
                LightningCommonGen::KIND,
                <Lightning as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}

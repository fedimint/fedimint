#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]

mod db;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, anyhow, ensure, format_err};
use bls12_381::{G1Projective, Scalar};
use fedimint_bitcoind::create_bitcoind;
use fedimint_bitcoind::shared::ServerModuleSharedBitcoin;
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, ApiError, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, SupportedModuleApiVersions,
    TransactionItemAmount, api_endpoint,
};
use fedimint_core::task::timeout;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    BitcoinHash, InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send,
    push_db_pair_items,
};
use fedimint_lnv2_common::config::{
    LightningClientConfig, LightningConfig, LightningConfigConsensus, LightningConfigLocal,
    LightningConfigPrivate, LightningGenParams,
};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT,
    CONSENSUS_BLOCK_COUNT_ENDPOINT, DECRYPTION_KEY_SHARE_ENDPOINT, GATEWAYS_ENDPOINT,
    OUTGOING_CONTRACT_EXPIRATION_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_lnv2_common::{
    ContractId, LightningCommonInit, LightningConsensusItem, LightningInput, LightningInputError,
    LightningInputV0, LightningModuleTypes, LightningOutput, LightningOutputError,
    LightningOutputOutcome, LightningOutputV0, MODULE_CONSENSUS_VERSION, OutgoingWitness,
};
use fedimint_logging::LOG_MODULE_LNV2;
use fedimint_server::config::distributedgen::{PeerHandleOps, eval_poly_g1};
use fedimint_server::core::{
    DynServerModule, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_server::net::api::check_auth;
use futures::StreamExt;
use group::Curve;
use group::ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use strum::IntoEnumIterator;
use tokio::sync::watch;
use tpe::{
    AggregatePublicKey, DecryptionKeyShare, PublicKeyShare, SecretKeyShare, derive_pk_share,
};
use tracing::trace;

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, DecryptionKeyShareKey,
    DecryptionKeySharePrefix, GatewayKey, GatewayPrefix, IncomingContractKey,
    IncomingContractPrefix, OutgoingContractKey, OutgoingContractPrefix, PreimageKey,
    PreimagePrefix, UnixTimeVoteKey, UnixTimeVotePrefix,
};

#[derive(Debug, Clone)]
pub struct LightningInit;

impl ModuleInit for LightningInit {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut lightning: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();

        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        lightning,
                        "Lightning Block Count Votes"
                    );
                }
                DbKeyPrefix::UnixTimeVote => {
                    push_db_pair_items!(
                        dbtx,
                        UnixTimeVotePrefix,
                        UnixTimeVoteKey,
                        u64,
                        lightning,
                        "Lightning Unix Time Votes"
                    );
                }
                DbKeyPrefix::OutgoingContract => {
                    push_db_pair_items!(
                        dbtx,
                        OutgoingContractPrefix,
                        LightningOutgoingContractKey,
                        OutgoingContract,
                        lightning,
                        "Lightning Outgoing Contracts"
                    );
                }
                DbKeyPrefix::IncomingContract => {
                    push_db_pair_items!(
                        dbtx,
                        IncomingContractPrefix,
                        LightningIncomingContractKey,
                        IncomingContract,
                        lightning,
                        "Lightning Incoming Contracts"
                    );
                }
                DbKeyPrefix::DecryptionKeyShare => {
                    push_db_pair_items!(
                        dbtx,
                        DecryptionKeySharePrefix,
                        DecryptionKeyShareKey,
                        DecryptionKeyShare,
                        lightning,
                        "Lightning Decryption Key Share"
                    );
                }
                DbKeyPrefix::Preimage => {
                    push_db_pair_items!(
                        dbtx,
                        PreimagePrefix,
                        LightningPreimageKey,
                        [u8; 32],
                        lightning,
                        "Lightning Preimages"
                    );
                }
                DbKeyPrefix::Gateway => {
                    push_db_pair_items!(
                        dbtx,
                        GatewayPrefix,
                        GatewayKey,
                        (),
                        lightning,
                        "Lightning Gateways"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for LightningInit {
    type Module = Lightning;
    type Params = LightningGenParams;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Lightning::new(args.cfg().to_typed()?, &args.shared())
            .await?
            .into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self
            .parse_params(params)
            .expect("Failed tp parse lnv2 config gen params");

        let tpe_pks = peers
            .iter()
            .map(|peer| (*peer, dealer_pk(peers.to_num_peers(), *peer)))
            .collect::<BTreeMap<PeerId, PublicKeyShare>>();

        peers
            .iter()
            .map(|peer| {
                let cfg = LightningConfig {
                    local: LightningConfigLocal {
                        bitcoin_rpc: params.local.bitcoin_rpc.clone(),
                    },
                    consensus: LightningConfigConsensus {
                        tpe_agg_pk: dealer_agg_pk(),
                        tpe_pks: tpe_pks.clone(),
                        fee_consensus: params.consensus.fee_consensus.clone(),
                        network: params.consensus.network,
                    },
                    private: LightningConfigPrivate {
                        sk: dealer_sk(peers.to_num_peers(), *peer),
                    },
                };

                (*peer, cfg.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let (polynomial, sks) = peers.run_dkg_g1().await?;

        let server = LightningConfig {
            local: LightningConfigLocal {
                bitcoin_rpc: params.local.bitcoin_rpc.clone(),
            },
            consensus: LightningConfigConsensus {
                tpe_agg_pk: tpe::AggregatePublicKey(polynomial[0].to_affine()),
                tpe_pks: peers
                    .num_peers()
                    .peer_ids()
                    .map(|peer| (peer, PublicKeyShare(eval_poly_g1(&polynomial, &peer))))
                    .collect(),
                fee_consensus: params.consensus.fee_consensus.clone(),
                network: params.consensus.network,
            },
            private: LightningConfigPrivate {
                sk: SecretKeyShare(sks),
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<LightningConfig>()?;

        ensure!(
            tpe::derive_pk_share(&config.private.sk)
                == *config
                    .consensus
                    .tpe_pks
                    .get(identity)
                    .context("Public key set has no key for our identity")?,
            "Preimge encryption secret key share does not match our public key share"
        );

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<LightningClientConfig> {
        let config = LightningConfigConsensus::from_erased(config)?;
        Ok(LightningClientConfig {
            tpe_agg_pk: config.tpe_agg_pk,
            tpe_pks: config.tpe_pks,
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

fn dealer_agg_pk() -> AggregatePublicKey {
    AggregatePublicKey((G1Projective::generator() * coefficient(0)).to_affine())
}

fn dealer_pk(num_peers: NumPeers, peer: PeerId) -> PublicKeyShare {
    derive_pk_share(&dealer_sk(num_peers, peer))
}

fn dealer_sk(num_peers: NumPeers, peer: PeerId) -> SecretKeyShare {
    let x = Scalar::from(peer.to_usize() as u64 + 1);

    // We evaluate the scalar polynomial of degree threshold - 1 at the point x
    // using the Horner schema.

    let y = (0..num_peers.threshold())
        .map(|index| coefficient(index as u64))
        .rev()
        .reduce(|accumulator, c| accumulator * x + c)
        .expect("We have at least one coefficient");

    SecretKeyShare(y)
}

fn coefficient(index: u64) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(
        *index.consensus_hash::<sha256::Hash>().as_byte_array(),
    ))
}

#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
    /// Block count updated periodically by a background task
    block_count_rx: watch::Receiver<Option<u64>>,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Init = LightningInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        // We reduce the time granularity to deduplicate votes more often and not save
        // one consensus item every second.
        let mut items = vec![LightningConsensusItem::UnixTimeVote(
            60 * (duration_since_epoch().as_secs() / 60),
        )];

        if let Ok(block_count) = self.get_block_count() {
            trace!(target: LOG_MODULE_LNV2, ?block_count, "Proposing block count");
            items.push(LightningConsensusItem::BlockCountVote(block_count));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: LightningConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        trace!(target: LOG_MODULE_LNV2, ?consensus_item, "Processing consensus item proposal");
        match consensus_item {
            LightningConsensusItem::BlockCountVote(vote) => {
                let current_vote = dbtx
                    .insert_entry(&BlockCountVoteKey(peer), &vote)
                    .await
                    .unwrap_or(0);

                ensure!(current_vote < vote, "Block count vote is redundant");

                Ok(())
            }
            LightningConsensusItem::UnixTimeVote(vote) => {
                let current_vote = dbtx
                    .insert_entry(&UnixTimeVoteKey(peer), &vote)
                    .await
                    .unwrap_or(0);

                ensure!(current_vote < vote, "Unix time vote is redundant");

                Ok(())
            }
            LightningConsensusItem::Default { variant, .. } => Err(anyhow!(
                "Received lnv2 consensus item with unknown variant {variant}"
            )),
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b LightningInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, LightningInputError> {
        let (pub_key, amount) = match input.ensure_v0_ref()? {
            LightningInputV0::Outgoing(contract_id, outgoing_witness) => {
                let contract = dbtx
                    .remove_entry(&OutgoingContractKey(*contract_id))
                    .await
                    .ok_or(LightningInputError::UnknownContract)?;

                let pub_key = match outgoing_witness {
                    OutgoingWitness::Claim(preimage) => {
                        if contract.expiration <= self.consensus_block_count(dbtx).await {
                            return Err(LightningInputError::Expired);
                        }

                        if !contract.verify_preimage(preimage) {
                            return Err(LightningInputError::InvalidPreimage);
                        }

                        dbtx.insert_entry(&PreimageKey(*contract_id), preimage)
                            .await;

                        contract.claim_pk
                    }
                    OutgoingWitness::Refund => {
                        if contract.expiration > self.consensus_block_count(dbtx).await {
                            return Err(LightningInputError::NotExpired);
                        }

                        contract.refund_pk
                    }
                    OutgoingWitness::Cancel(forfeit_signature) => {
                        if !contract.verify_forfeit_signature(forfeit_signature) {
                            return Err(LightningInputError::InvalidForfeitSignature);
                        }

                        contract.refund_pk
                    }
                };

                (pub_key, contract.amount)
            }
            LightningInputV0::Incoming(contract_id, agg_decryption_key) => {
                let contract = dbtx
                    .remove_entry(&IncomingContractKey(*contract_id))
                    .await
                    .ok_or(LightningInputError::UnknownContract)?;

                if !contract
                    .verify_agg_decryption_key(&self.cfg.consensus.tpe_agg_pk, agg_decryption_key)
                {
                    return Err(LightningInputError::InvalidDecryptionKey);
                }

                let pub_key = match contract.decrypt_preimage(agg_decryption_key) {
                    Some(..) => contract.commitment.claim_pk,
                    None => contract.commitment.refund_pk,
                };

                (pub_key, contract.commitment.amount)
            }
        };

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount,
                fee: self.cfg.consensus.fee_consensus.fee(amount),
            },
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        _outpoint: OutPoint,
    ) -> Result<TransactionItemAmount, LightningOutputError> {
        let amount = match output.ensure_v0_ref()? {
            LightningOutputV0::Outgoing(contract) => {
                if dbtx
                    .insert_entry(&OutgoingContractKey(contract.contract_id()), contract)
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::ContractAlreadyExists);
                }

                contract.amount
            }
            LightningOutputV0::Incoming(contract) => {
                if !contract.verify() {
                    return Err(LightningOutputError::InvalidContract);
                }

                if contract.commitment.expiration <= self.consensus_unix_time(dbtx).await {
                    return Err(LightningOutputError::ContractExpired);
                }

                if dbtx
                    .insert_entry(&IncomingContractKey(contract.contract_id()), contract)
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::ContractAlreadyExists);
                }

                let dk_share = contract.create_decryption_key_share(&self.cfg.private.sk);

                dbtx.insert_entry(&DecryptionKeyShareKey(contract.contract_id()), &dk_share)
                    .await;

                contract.commitment.amount
            }
        };

        Ok(TransactionItemAmount {
            amount,
            fee: self.cfg.consensus.fee_consensus.fee(amount),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // Both incoming and outgoing contracts represent liabilities to the federation
        // since they are obligations to issue notes.
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &OutgoingContractPrefix,
                |_, contract| -(contract.amount.msats as i64),
            )
            .await;

        audit
            .add_items(
                dbtx,
                module_instance_id,
                &IncomingContractPrefix,
                |_, contract| -(contract.commitment.amount.msats as i64),
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                CONSENSUS_BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, _params : () | -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            api_endpoint! {
                AWAIT_INCOMING_CONTRACT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, params: (ContractId, u64) | -> Option<ContractId> {
                    let db = context.db();

                    Ok(module.await_incoming_contract(db, params.0, params.1).await)
                }
            },
            api_endpoint! {
                AWAIT_PREIMAGE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, params: (ContractId, u64)| -> Option<[u8; 32]> {
                    let db = context.db();

                    Ok(module.await_preimage(db, params.0, params.1).await)
                }
            },
            api_endpoint! {
                DECRYPTION_KEY_SHARE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Lightning, context, params: ContractId| -> DecryptionKeyShare {
                    let share = context
                        .db()
                        .begin_transaction_nc()
                        .await
                        .get_value(&DecryptionKeyShareKey(params))
                        .await
                        .ok_or(ApiError::bad_request("No decryption key share found".to_string()))?;

                    Ok(share)
                }
            },
            api_endpoint! {
                OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> Option<u64> {
                    let db = context.db();

                    Ok(module.outgoing_contract_expiration(db, contract_id).await)
                }
            },
            api_endpoint! {
                ADD_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Lightning, context, gateway: SafeUrl| -> bool {
                    check_auth(context)?;

                    let db = context.db();

                    Ok(Lightning::add_gateway(db, gateway).await)
                }
            },
            api_endpoint! {
                REMOVE_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Lightning, context, gateway: SafeUrl| -> bool {
                    check_auth(context)?;

                    let db = context.db();

                    Ok(Lightning::remove_gateway(db, gateway).await)
                }
            },
            api_endpoint! {
                GATEWAYS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Lightning, context, _params : () | -> Vec<SafeUrl> {
                    let db = context.db();

                    Ok(Lightning::gateways(db).await)
                }
            },
        ]
    }
}

impl Lightning {
    async fn new(
        cfg: LightningConfig,
        shared_bitcoin: &ServerModuleSharedBitcoin,
    ) -> anyhow::Result<Self> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc)?;
        let block_count_rx = shared_bitcoin
            .block_count_receiver(cfg.consensus.network, btc_rpc.clone())
            .await;

        Ok(Lightning {
            cfg,
            block_count_rx,
        })
    }

    fn get_block_count(&self) -> anyhow::Result<u64> {
        self.block_count_rx
            .borrow()
            .ok_or_else(|| format_err!("Block count not available yet"))
    }

    async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.tpe_pks.to_num_peers();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        counts.sort_unstable();

        counts.reverse();

        assert!(counts.last() <= counts.first());

        // The block count we select guarantees that any threshold of correct peers can
        // increase the consensus block count and any consensus block count has been
        // confirmed by a threshold of peers.

        counts.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    async fn consensus_unix_time(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.tpe_pks.to_num_peers();

        let mut times = dbtx
            .find_by_prefix(&UnixTimeVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        times.sort_unstable();

        times.reverse();

        assert!(times.last() <= times.first());

        // The unix time we select guarantees that any threshold of correct peers can
        // advance the consensus unix time and any consensus unix time has been
        // confirmed by a threshold of peers.

        times.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    async fn await_incoming_contract(
        &self,
        db: Database,
        contract_id: ContractId,
        expiration: u64,
    ) -> Option<ContractId> {
        loop {
            timeout(
                Duration::from_secs(10),
                db.wait_key_exists(&IncomingContractKey(contract_id)),
            )
            .await
            .ok();

            // to avoid race conditions we have to check for the contract and
            // its expiration in the same database transaction
            let mut dbtx = db.begin_transaction_nc().await;

            if let Some(contract) = dbtx.get_value(&IncomingContractKey(contract_id)).await {
                return Some(contract.contract_id());
            }

            if expiration <= self.consensus_unix_time(&mut dbtx).await {
                return None;
            }
        }
    }

    async fn await_preimage(
        &self,
        db: Database,
        contract_id: ContractId,
        expiration: u64,
    ) -> Option<[u8; 32]> {
        loop {
            timeout(
                Duration::from_secs(10),
                db.wait_key_exists(&PreimageKey(contract_id)),
            )
            .await
            .ok();

            // to avoid race conditions we have to check for the preimage and
            // the contracts expiration in the same database transaction
            let mut dbtx = db.begin_transaction_nc().await;

            if let Some(preimage) = dbtx.get_value(&PreimageKey(contract_id)).await {
                return Some(preimage);
            }

            if expiration <= self.consensus_block_count(&mut dbtx).await {
                return None;
            }
        }
    }

    async fn outgoing_contract_expiration(
        &self,
        db: Database,
        contract_id: ContractId,
    ) -> Option<u64> {
        let mut dbtx = db.begin_transaction_nc().await;

        let contract = dbtx.get_value(&OutgoingContractKey(contract_id)).await?;

        let consensus_block_count = self.consensus_block_count(&mut dbtx).await;

        Some(contract.expiration.saturating_sub(consensus_block_count))
    }

    async fn add_gateway(db: Database, gateway: SafeUrl) -> bool {
        let mut dbtx = db.begin_transaction().await;

        let is_new_entry = dbtx.insert_entry(&GatewayKey(gateway), &()).await.is_none();

        dbtx.commit_tx().await;

        is_new_entry
    }

    async fn remove_gateway(db: Database, gateway: SafeUrl) -> bool {
        let mut dbtx = db.begin_transaction().await;

        let entry_existed = dbtx.remove_entry(&GatewayKey(gateway)).await.is_some();

        dbtx.commit_tx().await;

        entry_existed
    }

    async fn gateways(db: Database) -> Vec<SafeUrl> {
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&GatewayPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await
    }
}

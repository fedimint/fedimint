#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]

mod db;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context};
use bls12_381::{G1Projective, Scalar};
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_core::bitcoin_migration::{
    bitcoin30_to_bitcoin32_secp256k1_pubkey, bitcoin32_to_bitcoin30_secp256k1_pubkey,
};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions,
    TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{timeout, TaskGroup};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, NumPeersExt, OutPoint, PeerId, ServerModule,
};
use fedimint_lnv2_common::config::{
    LightningClientConfig, LightningConfig, LightningConfigConsensus, LightningConfigLocal,
    LightningConfigPrivate, LightningGenParams,
};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT,
    CONSENSUS_BLOCK_COUNT_ENDPOINT, GATEWAYS_ENDPOINT, OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
    REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_lnv2_common::{
    ContractId, LightningCommonInit, LightningConsensusItem, LightningInput, LightningInputError,
    LightningInputV0, LightningModuleTypes, LightningOutput, LightningOutputError,
    LightningOutputOutcome, LightningOutputOutcomeV0, LightningOutputV0, OutgoingWitness,
    MODULE_CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::{evaluate_polynomial_g1, PeerHandleOps};
use fedimint_server::net::api::check_auth;
use futures::StreamExt;
use group::ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, GatewayKey, GatewayPrefix,
    IncomingContractKey, IncomingContractPrefix, LightningOutputOutcomePrefix, OutgoingContractKey,
    OutgoingContractPrefix, OutputOutcomeKey, PreimageKey, PreimagePrefix, UnixTimeVoteKey,
    UnixTimeVotePrefix,
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
                DbKeyPrefix::OutputOutcome => {
                    push_db_pair_items!(
                        dbtx,
                        LightningOutputOutcomePrefix,
                        LightningOutputOutcomeKey,
                        LightningOutputOutcome,
                        lightning,
                        "Lightning Output Outcomes"
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
        Ok(Lightning::new(args.cfg().to_typed()?, &args.task_group().clone())?.into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let (tpe_agg_pk, pks, sks) = dealer_keygen(peers.to_num_peers().threshold(), peers.len());

        let tpe_pks: BTreeMap<PeerId, PublicKeyShare> = peers.iter().copied().zip(pks).collect();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                (
                    peer,
                    LightningConfig {
                        local: LightningConfigLocal {
                            bitcoin_rpc: params.local.bitcoin_rpc.clone(),
                        },
                        consensus: LightningConfigConsensus {
                            tpe_agg_pk,
                            tpe_pks: tpe_pks.clone(),
                            fee_consensus: params.consensus.fee_consensus.clone(),
                            network: params.consensus.network,
                        },
                        private: LightningConfigPrivate {
                            sk: sks[peer.to_usize()],
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
        let (poly_g1, sk) = g1[&()].clone().tpe();

        let server = LightningConfig {
            local: LightningConfigLocal {
                bitcoin_rpc: params.local.bitcoin_rpc.clone(),
            },
            consensus: LightningConfigConsensus {
                tpe_agg_pk: tpe::AggregatePublicKey(poly_g1[0].to_affine()),
                tpe_pks: peers
                    .peer_ids()
                    .iter()
                    .map(|peer| {
                        let pk = evaluate_polynomial_g1(
                            &poly_g1,
                            &Scalar::from(peer.to_usize() as u64 + 1),
                        );

                        (*peer, PublicKeyShare(pk))
                    })
                    .collect(),
                fee_consensus: params.consensus.fee_consensus.clone(),
                network: params.consensus.network,
            },
            private: LightningConfigPrivate {
                sk: SecretKeyShare(sk),
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<LightningConfig>()?;

        ensure!(
            tpe::derive_public_key_share(&config.private.sk)
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
}

fn dealer_keygen(
    threshold: usize,
    keys: usize,
) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
    let mut rng = OsRng; // FIXME: pass rng
    let poly: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

    let apk = (G1Projective::generator() * eval_polynomial(&poly, &Scalar::zero())).to_affine();

    let sks: Vec<SecretKeyShare> = (0..keys)
        .map(|idx| SecretKeyShare(eval_polynomial(&poly, &Scalar::from(idx as u64 + 1))))
        .collect();

    let pks = sks
        .iter()
        .map(|sk| PublicKeyShare((G1Projective::generator() * sk.0).to_affine()))
        .collect();

    (AggregatePublicKey(apk), pks, sks)
}

fn eval_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
}

#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
    btc_rpc: DynBitcoindRpc,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Init = LightningInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        let mut items = vec![LightningConsensusItem::UnixTimeVote(
            duration_since_epoch().as_secs(),
        )];

        if let Ok(block_count) = self.btc_rpc.get_block_count().await {
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

                ensure!(
                    current_vote < vote,
                    "Unix time vote is redundant {current_vote} < {vote}"
                );

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
    ) -> Result<InputMeta, LightningInputError> {
        let input = input.ensure_v0_ref()?;

        let (pub_key, amount) = match &input {
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

                        dbtx.insert_new_entry(&PreimageKey(*contract_id), preimage)
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

                (
                    bitcoin32_to_bitcoin30_secp256k1_pubkey(&pub_key),
                    contract.amount,
                )
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

                (
                    bitcoin32_to_bitcoin30_secp256k1_pubkey(&pub_key),
                    contract.commitment.amount,
                )
            }
        };

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount,
                fee: self.cfg.consensus.fee_consensus.fee(amount),
            },
            pub_key: bitcoin30_to_bitcoin32_secp256k1_pubkey(&pub_key),
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, LightningOutputError> {
        let output = output.ensure_v0_ref()?;

        let outcome = match output {
            LightningOutputV0::Outgoing(contract) => {
                if dbtx
                    .insert_entry(&OutgoingContractKey(contract.contract_id()), contract)
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::ContractAlreadyExists);
                }

                LightningOutputOutcomeV0::Outgoing
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

                LightningOutputOutcomeV0::Incoming(dk_share)
            }
        };

        if dbtx
            .insert_entry(
                &OutputOutcomeKey(out_point),
                &LightningOutputOutcome::V0(outcome),
            )
            .await
            .is_some()
        {
            panic!("Output Outcome for {out_point:?} already exists");
        }

        let amount = match output {
            LightningOutputV0::Outgoing(contract) => contract.amount,
            LightningOutputV0::Incoming(contract) => contract.commitment.amount,
        };

        Ok(TransactionItemAmount {
            amount,
            fee: self.cfg.consensus.fee_consensus.fee(amount),
        })
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&OutputOutcomeKey(out_point)).await
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
    fn new(cfg: LightningConfig, task_group: &TaskGroup) -> anyhow::Result<Self> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc, task_group.make_handle())?;

        Ok(Lightning { cfg, btc_rpc })
    }

    async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.tpe_pks.to_num_peers();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        while counts.len() < num_peers.total() {
            counts.push(0);
        }

        assert_eq!(counts.len(), num_peers.total());

        counts.sort_unstable();

        assert!(counts.first() <= counts.last());

        // The block count we select guarantees that any threshold of correct peers can
        // increase the consensus block count and any consensus block count has been
        // confirmed by a threshold of peers.

        counts[num_peers.max_evil()]
    }

    async fn consensus_unix_time(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.tpe_pks.to_num_peers();

        let mut times = dbtx
            .find_by_prefix(&UnixTimeVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        while times.len() < num_peers.total() {
            times.push(0);
        }

        assert_eq!(times.len(), num_peers.total());

        times.sort_unstable();

        assert!(times.first() <= times.last());

        // The unix time we select guarantees that any threshold of correct peers can
        // advance the consensus unix time and any consensus unix time has been
        // confirmed by a threshold of peers.

        times[num_peers.max_evil()]
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
            .map(|entry| entry.0 .0)
            .collect()
            .await
    }
}

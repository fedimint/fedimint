mod db;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::ensure;
use bls12_381::{G1Projective, Scalar};
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::endpoint_constants::{
    AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT, CONSENSUS_BLOCK_COUNT_ENDPOINT,
    OUTGOING_CONTRACT_EXPIRATION_ENDPOINT,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions,
    TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{timeout, TaskGroup};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_pair_items, NumPeersExt, OutPoint, PeerId, ServerModule,
};
use fedimint_lnv2_common::config::{
    FeeConsensus, LightningClientConfig, LightningConfig, LightningConfigConsensus,
    LightningConfigLocal, LightningConfigPrivate, LightningGenParams,
};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{
    ContractId, LightningCommonInit, LightningConsensusItem, LightningInput, LightningInputError,
    LightningModuleTypes, LightningOutput, LightningOutputError, LightningOutputOutcome,
    OutgoingWitness, Witness,
};
use fedimint_server::config::distributedgen::{evaluate_polynomial_g1, PeerHandleOps};
use futures::StreamExt;
use group::ff::Field;
use group::Curve;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, IncomingContractKey,
    IncomingContractPrefix, LightningOutputOutcomePrefix, OutgoingContractKey,
    OutgoingContractPrefix, OutputOutcomeKey, PreimageKey, PreimagePrefix, UnixTimeVoteKey,
    UnixTimeVotePrefix,
};

#[derive(Debug, Clone)]
pub struct LightningInit;

impl ModuleInit for LightningInit {
    type Common = LightningCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

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
            }
        }

        Box::new(lightning.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for LightningInit {
    type Params = LightningGenParams;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion { major: 0, minor: 0 }]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Lightning::new(args.cfg().to_typed()?, &mut args.task_group().clone())?.into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let (tpe_agg_pk, pks, sks) = dealer_keygen(peers.threshold(), peers.len());

        let tpe_pks: BTreeMap<PeerId, PublicKeyShare> = peers.iter().cloned().zip(pks).collect();

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
                            fee_consensus: FeeConsensus::default(),
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
                fee_consensus: Default::default(),
                network: params.consensus.network,
            },
            private: LightningConfigPrivate {
                sk: SecretKeyShare(sk),
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
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
        .cloned()
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

                ensure!(current_vote < vote, "Unix time vote is redundant");

                Ok(())
            }
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b LightningInput,
    ) -> Result<InputMeta, LightningInputError> {
        let (pub_key, amount) = match &input.witness {
            Witness::Outgoing(contract_id, outgoing_witness) => {
                let contract = dbtx
                    .remove_entry(&OutgoingContractKey(*contract_id))
                    .await
                    .ok_or(LightningInputError::UnknownContract)?;

                match outgoing_witness {
                    OutgoingWitness::Claim(preimage) => {
                        if contract.expiration <= self.consensus_block_count(dbtx).await {
                            return Err(LightningInputError::Expired);
                        }

                        if !contract.verify_preimage(preimage) {
                            return Err(LightningInputError::InvalidPreimage);
                        }

                        dbtx.insert_new_entry(&PreimageKey(*contract_id), preimage)
                            .await;

                        (contract.claim_pk, contract.amount)
                    }
                    OutgoingWitness::Refund => {
                        if contract.expiration > self.consensus_block_count(dbtx).await {
                            return Err(LightningInputError::NotExpired);
                        }

                        (contract.refund_pk, contract.amount)
                    }
                    OutgoingWitness::Cancel(forfeit_signature) => {
                        if !contract.verify_forfeit_signature(forfeit_signature) {
                            return Err(LightningInputError::InvalidForfeitSignature);
                        }

                        (contract.refund_pk, contract.amount)
                    }
                }
            }
            Witness::Incoming(contract_id, agg_decryption_key) => {
                let contract = dbtx
                    .remove_entry(&IncomingContractKey(*contract_id))
                    .await
                    .ok_or(LightningInputError::UnknownContract)?;

                if !contract
                    .verify_agg_decryption_key(&self.cfg.consensus.tpe_agg_pk, agg_decryption_key)
                {
                    return Err(LightningInputError::InvalidDecryptionKey);
                }

                match contract.decrypt_preimage(agg_decryption_key) {
                    Some(..) => (contract.commitment.claim_pk, contract.commitment.amount),
                    None => (contract.commitment.refund_pk, contract.commitment.amount),
                }
            }
        };

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount,
                fee: self.cfg.consensus.fee_consensus.input,
            },
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, LightningOutputError> {
        let outcome = match output {
            LightningOutput::Outgoing(contract) => {
                if dbtx
                    .insert_entry(&OutgoingContractKey(contract.contract_id()), contract)
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::ContractAlreadyExists);
                }

                LightningOutputOutcome::Outgoing
            }
            LightningOutput::Incoming(contract) => {
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

                let decryption_key_share =
                    contract.create_decryption_key_share(&self.cfg.private.sk);

                LightningOutputOutcome::Incoming(decryption_key_share)
            }
        };

        if dbtx
            .insert_entry(&OutputOutcomeKey(out_point), &outcome)
            .await
            .is_some()
        {
            panic!("Output Outcome for {:?} already exists", out_point);
        }

        Ok(TransactionItemAmount {
            amount: output.amount(),
            fee: self.cfg.consensus.fee_consensus.output,
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
                async |module: &Lightning, context, _params: ()| -> u64 {
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
        ]
    }
}

impl Lightning {
    fn new(cfg: LightningConfig, task_group: &mut TaskGroup) -> anyhow::Result<Self> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc, task_group.make_handle())?;

        Ok(Lightning { cfg, btc_rpc })
    }

    async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let peer_count = self.cfg.consensus.tpe_pks.len();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        assert!(counts.len() <= peer_count);

        while counts.len() < peer_count {
            counts.push(0);
        }

        counts.sort_unstable();

        counts[peer_count / 2]
    }

    async fn consensus_unix_time(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let peer_count = self.cfg.consensus.tpe_pks.len();

        let mut times = dbtx
            .find_by_prefix(&UnixTimeVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        assert!(times.len() <= peer_count);

        while times.len() < peer_count {
            times.push(0);
        }

        times.sort_unstable();

        times[peer_count / 2]
    }

    async fn await_incoming_contract(
        &self,
        db: Database,
        contract_id: ContractId,
        expiration: u64,
    ) -> Option<ContractId> {
        loop {
            timeout(
                Duration::from_secs(60 * 10),
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
                Duration::from_secs(60 * 10),
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
}

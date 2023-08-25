use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;

use anyhow::{bail, Context};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, ModuleDatabaseTransaction};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ConsensusProposal, CoreConsensusVersion,
    ExtendsCommonModuleInit, InputMeta, IntoModuleError, ModuleConsensusVersion, ModuleError,
    PeerHandle, ServerModuleInit, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::{MaybeSend, TaskGroup};
use fedimint_core::tiered::InvalidAmountTierError;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_key_items, push_db_pair_items, Amount, NumPeers,
    OutPoint, PeerId, ServerModule, Tiered, TieredMulti, TieredMultiZip,
};
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::{
    FeeConsensus, MintClientConfig, MintConfig, MintConfigConsensus, MintConfigLocal,
    MintConfigPrivate, MintGenParams,
};
use fedimint_mint_common::db::{
    DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix, MintAuditItemKey,
    MintAuditItemKeyPrefix, NonceKey, NonceKeyPrefix, OutputOutcomeKey, OutputOutcomeKeyPrefix,
    ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix, ReceivedPartialSignatureKey,
    ReceivedPartialSignatureKeyOutputPrefix, ReceivedPartialSignaturesKeyPrefix,
};
pub use fedimint_mint_common::{BackupRequest, SignedBackupRequest};
use fedimint_mint_common::{
    BlindNonce, MintCommonGen, MintConsensusItem, MintError, MintInput, MintModuleTypes,
    MintOutput, MintOutputBlindSignatures, MintOutputOutcome, MintOutputSignatureShare,
    DEFAULT_MAX_NOTES_PER_DENOMINATION,
};
use fedimint_server::config::distributedgen::{scalar, PeerHandleOps};
use futures::StreamExt;
use itertools::Itertools;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelBridge;
use secp256k1_zkp::SECP256K1;
use strum::IntoEnumIterator;
use tbs::{
    combine_valid_shares, dealer_keygen, sign_blinded_msg, verify_blind_share, Aggregatable,
    AggregatePublicKey, PublicKeyShare, SecretKeyShare,
};
use threshold_crypto::group::Curve;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct MintGen;

impl ExtendsCommonModuleInit for MintGen {
    type Common = MintCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for MintGen {
    type Params = MintGenParams;
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
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Mint::new(cfg.to_typed()?).into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let tbs_keys = params
            .consensus
            .mint_amounts
            .iter()
            .map(|&amount| {
                let (tbs_pk, tbs_pks, tbs_sks) = dealer_keygen(peers.threshold(), peers.len());
                (amount, (tbs_pk, tbs_pks, tbs_sks))
            })
            .collect::<HashMap<_, _>>();

        let mint_cfg: BTreeMap<_, MintConfig> = peers
            .iter()
            .map(|&peer| {
                let config = MintConfig {
                    local: MintConfigLocal,
                    consensus: MintConfigConsensus {
                        peer_tbs_pks: peers
                            .iter()
                            .map(|&key_peer| {
                                let keys = params
                                    .consensus
                                    .mint_amounts
                                    .iter()
                                    .map(|amount| {
                                        (*amount, tbs_keys[amount].1[key_peer.to_usize()])
                                    })
                                    .collect();
                                (key_peer, keys)
                            })
                            .collect(),
                        fee_consensus: FeeConsensus::default(),
                        max_notes_per_denomination: DEFAULT_MAX_NOTES_PER_DENOMINATION,
                    },
                    private: MintConfigPrivate {
                        tbs_sks: params
                            .consensus
                            .mint_amounts
                            .iter()
                            .map(|amount| (*amount, tbs_keys[amount].2[peer.to_usize()]))
                            .collect(),
                    },
                };
                (peer, config)
            })
            .collect();

        mint_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let g2 = peers
            .run_dkg_multi_g2(params.consensus.mint_amounts.to_vec())
            .await?;

        let amounts_keys = g2
            .into_iter()
            .map(|(amount, keys)| (amount, keys.tbs()))
            .collect::<HashMap<_, _>>();

        let server = MintConfig {
            local: MintConfigLocal,
            private: MintConfigPrivate {
                tbs_sks: amounts_keys
                    .iter()
                    .map(|(amount, (_, sks))| (*amount, *sks))
                    .collect(),
            },
            consensus: MintConfigConsensus {
                peer_tbs_pks: peers
                    .peer_ids()
                    .iter()
                    .map(|peer| {
                        let pks = amounts_keys
                            .iter()
                            .map(|(amount, (pks, _))| {
                                let pks = PublicKeyShare(pks.evaluate(scalar(peer)).to_affine());
                                (*amount, pks)
                            })
                            .collect::<Tiered<_>>();

                        (*peer, pks)
                    })
                    .collect(),
                fee_consensus: Default::default(),
                max_notes_per_denomination: DEFAULT_MAX_NOTES_PER_DENOMINATION,
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<MintConfig>()?;
        let sks: BTreeMap<Amount, PublicKeyShare> = config
            .private
            .tbs_sks
            .iter()
            .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
            .collect();
        let pks: BTreeMap<Amount, PublicKeyShare> = config
            .consensus
            .peer_tbs_pks
            .get(identity)
            .unwrap()
            .as_map()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        if sks != pks {
            bail!("Mint private key doesn't match pubkey share");
        }
        if !sks.keys().contains(&Amount::from_msats(1)) {
            bail!("No msat 1 denomination");
        }

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<MintClientConfig> {
        let config = MintConfigConsensus::from_erased(config)?;
        let pub_keys = TieredMultiZip::new(
            config
                .peer_tbs_pks
                .values()
                .map(|keys| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let agg_key = keys
                .into_iter()
                .copied()
                .collect::<Vec<_>>()
                .aggregate(config.peer_tbs_pks.threshold());
            (amt, agg_key)
        });

        Ok(MintClientConfig {
            tbs_pks: Tiered::from_iter(pub_keys),
            fee_consensus: config.fee_consensus.clone(),
            peer_tbs_pks: config.peer_tbs_pks.clone(),
            max_notes_per_denomination: config.max_notes_per_denomination,
        })
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut mint: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::NoteNonce => {
                    push_db_key_items!(dbtx, NonceKeyPrefix, NonceKey, mint, "Used Coins");
                }
                DbKeyPrefix::MintAuditItem => {
                    push_db_pair_items!(
                        dbtx,
                        MintAuditItemKeyPrefix,
                        MintAuditItemKey,
                        fedimint_core::Amount,
                        mint,
                        "Mint Audit Items"
                    );
                }
                DbKeyPrefix::OutputOutcome => {
                    push_db_pair_items!(
                        dbtx,
                        OutputOutcomeKeyPrefix,
                        OutputOutcomeKey,
                        MintOutputBlindSignatures,
                        mint,
                        "Output Outcomes"
                    );
                }
                DbKeyPrefix::ProposedPartialSig => {
                    push_db_pair_items!(
                        dbtx,
                        ProposedPartialSignaturesKeyPrefix,
                        ProposedPartialSignatureKey,
                        MintOutputSignatureShare,
                        mint,
                        "Proposed Signature Shares"
                    );
                }
                DbKeyPrefix::ReceivedPartialSig => {
                    push_db_pair_items!(
                        dbtx,
                        ReceivedPartialSignaturesKeyPrefix,
                        ReceivedPartialSignatureKey,
                        MintOutputSignatureShare,
                        mint,
                        "Received Signature Shares"
                    );
                }
                DbKeyPrefix::EcashBackup => {
                    push_db_pair_items!(
                        dbtx,
                        EcashBackupKeyPrefix,
                        EcashBackupKey,
                        ECashUserBackupSnapshot,
                        mint,
                        "User Ecash Backup"
                    );
                }
            }
        }

        Box::new(mint.into_iter())
    }
}
/// Federated mint member mint
#[derive(Debug)]
pub struct Mint {
    cfg: MintConfig,
    sec_key: Tiered<SecretKeyShare>,
    pub_key_shares: BTreeMap<PeerId, Tiered<PublicKeyShare>>,
    pub_key: HashMap<Amount, AggregatePublicKey>,
}
#[apply(async_trait_maybe_send!)]
impl ServerModule for Mint {
    type Common = MintModuleTypes;
    type Gen = MintGen;
    type VerificationCache = VerificationCache;

    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>) {
        if !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<MintConsensusItem> {
        ConsensusProposal::new_auto_trigger(
            dbtx.find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
                .await
                .map(|(key, signatures)| MintConsensusItem {
                    out_point: key.0,
                    signatures,
                })
                .collect::<Vec<MintConsensusItem>>()
                .await,
        )
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_item: MintConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let out_point = consensus_item.out_point;
        let signatures = consensus_item.signatures;

        if dbtx.get_value(&OutputOutcomeKey(out_point)).await.is_some() {
            bail!("Already obtained a threshold of blind signature shares")
        }

        if dbtx
            .get_value(&ReceivedPartialSignatureKey(out_point, peer_id))
            .await
            .is_some()
        {
            bail!("Already received a valid signature share by this peer");
        }

        // check if we are collecting signature shares for this out_point
        let our_contribution = dbtx
            .get_value(&ProposedPartialSignatureKey(out_point))
            .await
            .context("Out point for this signature share does not exist")?;

        // check if we have received one signature per blinded note
        if !signatures.0.structural_eq(&our_contribution.0) {
            bail!("Signature share structure is invalid");
        }

        // obtain the correct messages to be signed from our contribution
        let reference_messages = our_contribution
            .0
            .iter_items()
            .map(|(_amt, (msg, _sig))| msg);

        // check if the received signatures are valid for the reference_messages
        if !signatures.0.iter_items().zip(reference_messages).all(
            // the key used for the signature is different for every peer and amount
            |((amount, (.., sig)), ref_msg)| match self.pub_key_shares[&peer_id].tier(&amount) {
                Ok(amount_key) => verify_blind_share(*ref_msg, *sig, *amount_key),
                Err(_) => false,
            },
        ) {
            bail!("Signature share signature is invalid");
        }

        // we save the first valid signature share by this peer
        dbtx.insert_new_entry(
            &ReceivedPartialSignatureKey(out_point, peer_id),
            &signatures,
        )
        .await;

        // retrieve all valid signature shares previously received for this out point
        let signature_shares = dbtx
            .find_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix(out_point))
            .await
            .map(|(key, partial_sig)| (key.1, partial_sig))
            .collect::<Vec<_>>()
            .await;

        // check if we have enough signature shares to combine
        if signature_shares.len() < self.cfg.consensus.peer_tbs_pks.threshold() {
            return Ok(());
        }

        // combine valid signature shares
        let blind_signatures = TieredMultiZip::new(
            signature_shares
                .iter()
                .map(|(_peer, sig_share)| sig_share.0.iter_items())
                .collect(),
        )
        .map(|(amt, sig_shares)| {
            let peer_ids = signature_shares.iter().map(|(peer, _)| *peer);

            let sig = combine_valid_shares(
                sig_shares
                    .into_iter()
                    .zip(peer_ids)
                    .map(|((.., share), peer)| (peer.to_usize(), *share)),
                self.cfg.consensus.peer_tbs_pks.threshold(),
            );

            (amt, sig)
        })
        .collect::<TieredMulti<_>>();

        dbtx.remove_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix(out_point))
            .await;

        dbtx.remove_entry(&ProposedPartialSignatureKey(out_point))
            .await;

        dbtx.insert_entry(
            &OutputOutcomeKey(out_point),
            &MintOutputBlindSignatures(blind_signatures),
        )
        .await;

        // TODO: move the db compaction somewhere more appropriate, possibly in the
        // audit method?
        let mut redemptions = Amount::from_sats(0);
        let mut issuances = Amount::from_sats(0);
        let remove_audit_keys = dbtx
            .find_by_prefix(&MintAuditItemKeyPrefix)
            .await
            .map(|(key, amount)| {
                match key {
                    MintAuditItemKey::Issuance(_) => issuances += amount,
                    MintAuditItemKey::IssuanceTotal => issuances += amount,
                    MintAuditItemKey::Redemption(_) => redemptions += amount,
                    MintAuditItemKey::RedemptionTotal => redemptions += amount,
                }
                key
            })
            .collect::<Vec<_>>()
            .await;

        for key in remove_audit_keys {
            dbtx.remove_entry(&key).await;
        }

        dbtx.insert_entry(&MintAuditItemKey::IssuanceTotal, &issuances)
            .await;
        dbtx.insert_entry(&MintAuditItemKey::RedemptionTotal, &redemptions)
            .await;

        Ok(())
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a MintInput> + MaybeSend,
    ) -> Self::VerificationCache {
        VerificationCache
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b MintInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let iter = input.iter_items();

        #[cfg(not(target_family = "wasm"))]
        let iter = iter.par_bridge();

        if !iter.all(|(amount, note)| match self.pub_key.get(&amount) {
            Some(amount_key) => note.verify(*amount_key),
            None => false,
        }) {
            return Err(MintError::InvalidSignature).into_module_error_other();
        }

        for (amount, note) in input.iter_items() {
            if dbtx.insert_entry(&NonceKey(note.0), &()).await.is_some() {
                return Err(MintError::SpentCoin).into_module_error_other();
            }

            dbtx.insert_new_entry(&MintAuditItemKey::Redemption(NonceKey(note.0)), &amount)
                .await;
        }

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.total_amount(),
                fee: self.cfg.consensus.fee_consensus.note_spend_abs * (input.count_items() as u64),
            },
            pub_keys: input
                .iter_items()
                .map(|(_, note)| *note.spend_key())
                .collect(),
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        output: &'a MintOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        let max_tier = self.cfg.private.tbs_sks.max_tier();
        if output.longest_tier_except(max_tier)
            > self.cfg.consensus.max_notes_per_denomination.into()
        {
            return Err(MintError::ExceededMaxNotes(
                self.cfg.consensus.max_notes_per_denomination,
                output.longest_tier_except(max_tier),
            ))
            .into_module_error_other();
        }

        if let Some(amount) = output.iter_items().find_map(|(amount, _)| {
            if self.pub_key.get(&amount).is_none() {
                Some(amount)
            } else {
                None
            }
        }) {
            return Err(MintError::InvalidAmountTier(amount)).into_module_error_other();
        }

        // TODO: move actual signing to worker thread
        // TODO: get rid of clone
        let partial_sig = self
            .blind_sign(output.clone().0)
            .into_module_error_other()?;

        dbtx.insert_new_entry(&ProposedPartialSignatureKey(out_point), &partial_sig)
            .await;
        dbtx.insert_new_entry(
            &MintAuditItemKey::Issuance(out_point),
            &output.total_amount(),
        )
        .await;

        Ok(TransactionItemAmount {
            amount: output.total_amount(),
            fee: self.cfg.consensus.fee_consensus.note_issuance_abs * (output.count_items() as u64),
        })
    }

    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<MintOutputOutcome> {
        let we_proposed = dbtx
            .get_value(&ProposedPartialSignatureKey(out_point))
            .await
            .is_some();
        let was_consensus_outcome = dbtx
            .find_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix(out_point))
            .await
            .collect::<Vec<_>>()
            .await
            .is_empty();

        let final_sig = dbtx.get_value(&OutputOutcomeKey(out_point)).await;

        if final_sig.is_some() {
            Some(MintOutputOutcome(final_sig))
        } else if we_proposed || was_consensus_outcome {
            Some(MintOutputOutcome(None))
        } else {
            None
        }
    }

    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(
                dbtx,
                common::KIND.as_str(),
                &MintAuditItemKeyPrefix,
                |k, v| match k {
                    MintAuditItemKey::Issuance(_) => -(v.msats as i64),
                    MintAuditItemKey::IssuanceTotal => -(v.msats as i64),
                    MintAuditItemKey::Redemption(_) => v.msats as i64,
                    MintAuditItemKey::RedemptionTotal => v.msats as i64,
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "backup",
                async |module: &Mint, context, request: SignedBackupRequest| -> () {
                    module
                        .handle_backup_request(&mut context.dbtx(), request).await?;
                    Ok(())
                }
            },
            api_endpoint! {
                "recover",
                async |module: &Mint, context, id: secp256k1_zkp::XOnlyPublicKey| -> Option<ECashUserBackupSnapshot> {
                    Ok(module
                        .handle_recover_request(&mut context.dbtx(), id).await)
                }
            },
        ]
    }
}

impl Mint {
    async fn handle_backup_request(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        request: SignedBackupRequest,
    ) -> Result<(), ApiError> {
        let request = request
            .verify_valid(SECP256K1)
            .map_err(|_| ApiError::bad_request("invalid request".into()))?;

        debug!(id = %request.id, len = request.payload.len(), "Received user e-cash backup request");
        if let Some(prev) = dbtx.get_value(&EcashBackupKey(request.id)).await {
            if request.timestamp <= prev.timestamp {
                debug!(id = %request.id, len = request.payload.len(), "Received user e-cash backup request with old timestamp - ignoring");
                return Err(ApiError::bad_request("timestamp too small".into()));
            }
        }

        info!(id = %request.id, len = request.payload.len(), "Storing new user e-cash backup");
        dbtx.insert_entry(
            &EcashBackupKey(request.id),
            &ECashUserBackupSnapshot {
                timestamp: request.timestamp,
                data: request.payload.to_vec(),
            },
        )
        .await;

        Ok(())
    }

    async fn handle_recover_request(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        id: secp256k1_zkp::XOnlyPublicKey,
    ) -> Option<ECashUserBackupSnapshot> {
        dbtx.get_value(&EcashBackupKey(id)).await
    }
}

impl Mint {
    /// Constructs a new mint
    ///
    /// # Panics
    /// * If there are no amount tiers
    /// * If the amount tiers for secret and public keys are inconsistent
    /// * If the pub key belonging to the secret key share is not in the pub key
    ///   list.
    pub fn new(cfg: MintConfig) -> Mint {
        assert!(cfg.private.tbs_sks.tiers().count() > 0);

        // The amount tiers are implicitly provided by the key sets, make sure they are
        // internally consistent.
        assert!(cfg
            .consensus
            .peer_tbs_pks
            .values()
            .all(|pk| pk.structural_eq(&cfg.private.tbs_sks)));

        let ref_pub_key = cfg.private.tbs_sks.to_public();

        // Find our key index and make sure we know the private key for all our public
        // key shares
        let our_id = cfg
            .consensus // FIXME: make sure we use id instead of idx everywhere
            .peer_tbs_pks
            .iter()
            .find_map(|(&id, pk)| if *pk == ref_pub_key { Some(id) } else { None })
            .expect("Own key not found among pub keys.");

        assert_eq!(
            cfg.consensus.peer_tbs_pks[&our_id],
            cfg.private
                .tbs_sks
                .iter()
                .map(|(amount, sk)| (amount, sk.to_pub_key_share()))
                .collect()
        );

        let aggregate_pub_keys = TieredMultiZip::new(
            cfg.consensus
                .peer_tbs_pks
                .values()
                .map(|keys| keys.iter())
                .collect(),
        )
        .map(|(amt, keys)| {
            // TODO: avoid this through better aggregation API allowing references or
            let keys = keys.into_iter().copied().collect::<Vec<_>>();
            (amt, keys.aggregate(cfg.consensus.peer_tbs_pks.threshold()))
        })
        .collect();

        Mint {
            cfg: cfg.clone(),
            sec_key: cfg.private.tbs_sks,
            pub_key_shares: cfg.consensus.peer_tbs_pks.into_iter().collect(),
            pub_key: aggregate_pub_keys,
        }
    }

    pub fn pub_key(&self) -> HashMap<Amount, AggregatePublicKey> {
        self.pub_key.clone()
    }

    fn blind_sign(
        &self,
        output: TieredMulti<BlindNonce>,
    ) -> Result<MintOutputSignatureShare, MintError> {
        Ok(MintOutputSignatureShare(output.map(
            |amt, msg| -> Result<_, InvalidAmountTierError> {
                let sec_key = self.sec_key.tier(&amt)?;
                let blind_signature = sign_blinded_msg(msg.0, *sec_key);
                Ok((msg.0, blind_signature))
            },
        )?))
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use fedimint_core::config::{ClientModuleConfig, ConfigGenModuleParams, ServerModuleConfig};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::{ModuleConsensusVersion, ServerModuleInit};
    use fedimint_core::{Amount, PeerId, ServerModule};
    use fedimint_mint_common::config::FeeConsensus;
    use fedimint_mint_common::{MintInput, Nonce, Note};
    use tbs::blind_message;

    use crate::common::config::MintGenParamsConsensus;
    use crate::{
        Mint, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate, MintGen,
        MintGenParams, VerificationCache,
    };

    const MINTS: usize = 5;

    fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let mint_cfg = MintGen.trusted_dealer_gen(
            &peers,
            &ConfigGenModuleParams::from_typed(MintGenParams {
                local: Default::default(),
                consensus: MintGenParamsConsensus {
                    mint_amounts: vec![Amount::from_sats(1)],
                },
            })
            .unwrap(),
        );
        let client_cfg = ClientModuleConfig::from_typed(
            0,
            MintGen::kind(),
            ModuleConsensusVersion(0),
            MintGen
                .get_client_config(&mint_cfg[&PeerId::from(0)].consensus)
                .unwrap(),
        )
        .unwrap();

        (mint_cfg.into_values().collect(), client_cfg)
    }

    #[test_log::test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (mint_server_cfg1, _) = build_configs();
        let (mint_server_cfg2, _) = build_configs();

        Mint::new(MintConfig {
            local: MintConfigLocal,
            consensus: MintConfigConsensus {
                peer_tbs_pks: mint_server_cfg2[0]
                    .to_typed::<MintConfig>()
                    .unwrap()
                    .consensus
                    .peer_tbs_pks,
                fee_consensus: FeeConsensus::default(),
                max_notes_per_denomination: 0,
            },
            private: MintConfigPrivate {
                tbs_sks: mint_server_cfg1[0]
                    .to_typed::<MintConfig>()
                    .unwrap()
                    .private
                    .tbs_sks,
            },
        });
    }

    fn issue_note(
        server_cfgs: &[ServerModuleConfig],
        denomination: Amount,
    ) -> (secp256k1::KeyPair, Note) {
        let note_key = secp256k1::KeyPair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
        let nonce = Nonce(note_key.public_key().x_only_public_key().0);
        let message = nonce.to_message();
        let blinding_key = tbs::BlindingKey::random();
        let blind_msg = blind_message(message, blinding_key);

        let bsig_shares = server_cfgs
            .iter()
            .map(|cfg| {
                let sks = *cfg
                    .to_typed::<MintConfig>()
                    .unwrap()
                    .private
                    .tbs_sks
                    .get(denomination)
                    .unwrap();
                tbs::sign_blinded_msg(blind_msg, sks)
            })
            .enumerate()
            .collect::<Vec<_>>();

        let blind_signature = tbs::combine_valid_shares(
            bsig_shares,
            server_cfgs.len() - ((server_cfgs.len() - 1) / 3),
        );
        let sig = tbs::unblind_signature(blinding_key, blind_signature);

        (note_key, Note(nonce, sig))
    }

    #[test_log::test(tokio::test)]
    async fn test_detect_double_spends() {
        let (mint_server_cfg, _) = build_configs();

        let mint = Mint::new(mint_server_cfg[0].to_typed().unwrap());
        let (_, note) = issue_note(&mint_server_cfg, Amount::from_sats(1));

        // Normal spend works
        let db = Database::new(MemDatabase::new(), Default::default());
        let input = MintInput(vec![(Amount::from_sats(1), note)].into_iter().collect());

        // Double spend in same epoch is detected
        let mut dbtx = db.begin_transaction().await;
        mint.process_input(
            &mut dbtx.with_module_prefix(42),
            &input,
            &VerificationCache {},
        )
        .await
        .expect("Spend of valid e-cash works");
        assert_matches!(
            mint.process_input(
                &mut dbtx.with_module_prefix(42),
                &input,
                &VerificationCache {}
            )
            .await,
            Err(_)
        );

        // Double spend in same input is detected
        let mut dbtx = db.begin_transaction().await;
        let (_, note2) = issue_note(&mint_server_cfg, Amount::from_sats(1));
        let input2 = MintInput(
            vec![(Amount::from_sats(1), note2), (Amount::from_sats(1), note2)]
                .into_iter()
                .collect(),
        );
        assert_matches!(
            mint.process_input(
                &mut dbtx.with_module_prefix(42),
                &input2,
                &VerificationCache {}
            )
            .await,
            Err(_)
        );
    }
}

#[derive(Debug, Clone)]
pub struct VerificationCache;

impl fedimint_core::server::VerificationCache for VerificationCache {}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;

    use anyhow::{ensure, Context};
    use bitcoin_hashes::Hash;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
    use fedimint_core::db::{apply_migrations, DatabaseTransaction};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::{CommonModuleInit, DynServerModuleInit};
    use fedimint_core::time::now;
    use fedimint_core::{Amount, OutPoint, ServerModule, TieredMulti, TransactionId};
    use fedimint_mint_common::db::{
        DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix,
        MintAuditItemKey, MintAuditItemKeyPrefix, NonceKey, NonceKeyPrefix, OutputOutcomeKey,
        OutputOutcomeKeyPrefix, ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix,
        ReceivedPartialSignatureKey, ReceivedPartialSignaturesKeyPrefix,
    };
    use fedimint_mint_common::{
        MintCommonGen, MintOutputBlindSignatures, MintOutputSignatureShare, Nonce,
    };
    use fedimint_testing::db::{
        prepare_db_migration_snapshot, validate_migrations, BYTE_32, BYTE_8,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use tbs::{
        blind_message, combine_valid_shares, sign_blinded_msg, BlindingKey, FromRandom, Message,
        Scalar, SecretKeyShare,
    };

    use crate::{Mint, MintGen};

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let nonce_key = NonceKey(Nonce(pk.x_only_public_key().0));
        dbtx.insert_new_entry(&nonce_key, &()).await;

        let out_point = OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        };

        let blinding_key = BlindingKey::random();
        let message = Message::from_bytes(&BYTE_8);
        let blinded_message = blind_message(message, blinding_key);
        let secret_key_share = SecretKeyShare(Scalar::from_random(&mut OsRng));
        let blind_signature_share = sign_blinded_msg(blinded_message, secret_key_share);
        let mut tiers = BTreeMap::new();
        tiers.insert(
            Amount::from_sats(1000),
            vec![(blinded_message, blind_signature_share)],
        );
        let shares: TieredMulti<(tbs::BlindedMessage, tbs::BlindedSignatureShare)> =
            TieredMulti::new(tiers);

        dbtx.insert_new_entry(
            &ProposedPartialSignatureKey(out_point),
            &MintOutputSignatureShare(shares.clone()),
        )
        .await;

        dbtx.insert_new_entry(
            &ReceivedPartialSignatureKey(out_point, 1.into()),
            &MintOutputSignatureShare(shares),
        )
        .await;

        let mut sig_tiers = BTreeMap::new();
        let shares = vec![(0, blind_signature_share)].into_iter();
        let blind_sig = combine_valid_shares(shares, 1);
        sig_tiers.insert(Amount::from_sats(1000), vec![blind_sig]);
        let sigs: TieredMulti<tbs::BlindedSignature> = TieredMulti::new(sig_tiers);
        dbtx.insert_new_entry(
            &OutputOutcomeKey(out_point),
            &MintOutputBlindSignatures(sigs),
        )
        .await;

        let mint_audit_issuance = MintAuditItemKey::Issuance(out_point);
        let mint_audit_issuance_total = MintAuditItemKey::IssuanceTotal;
        let mint_audit_redemption = MintAuditItemKey::Redemption(nonce_key);
        let mint_audit_redemption_total = MintAuditItemKey::RedemptionTotal;

        dbtx.insert_new_entry(&mint_audit_issuance, &Amount::from_sats(1000))
            .await;
        dbtx.insert_new_entry(&mint_audit_issuance_total, &Amount::from_sats(5000))
            .await;
        dbtx.insert_new_entry(&mint_audit_redemption, &Amount::from_sats(10000))
            .await;
        dbtx.insert_new_entry(&mint_audit_redemption_total, &Amount::from_sats(15000))
            .await;

        let backup_key = EcashBackupKey(pk.x_only_public_key().0);
        let ecash_backup = ECashUserBackupSnapshot {
            timestamp: now(),
            data: BYTE_32.to_vec(),
        };
        dbtx.insert_new_entry(&backup_key, &ecash_backup).await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "mint-v0",
            |dbtx| {
                Box::pin(async move {
                    create_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                MintCommonGen::KIND,
                <Mint as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() {
        validate_migrations(
            "mint",
            |db| async move {
                let module = DynServerModuleInit::from(MintGen);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .context("Error applying migrations to temp database")?;

                // Verify that all of the data from the mint namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::NoteNonce => {
                            let nonces = dbtx
                                .find_by_prefix(&NonceKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_nonces = nonces.len();
                            ensure!(
                                num_nonces > 0,
                                "validate_migrations was not able to read any NoteNonces"
                            );
                        }
                        DbKeyPrefix::ProposedPartialSig => {
                            let proposed_partial_sigs = dbtx
                                .find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_sigs = proposed_partial_sigs.len();
                            ensure!(
                                num_sigs > 0,
                                "validate_migrations was not able to read any ProposedPartialSignatures"
                            );
                        }
                        DbKeyPrefix::ReceivedPartialSig => {
                            let received_partial_sigs = dbtx
                                .find_by_prefix(&ReceivedPartialSignaturesKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_sigs = received_partial_sigs.len();
                            ensure!(
                                num_sigs > 0,
                                "validate_migrations was not able to read any ReceivedPartialSignatures"
                            );
                        }
                        DbKeyPrefix::OutputOutcome => {
                            let outcomes = dbtx
                                .find_by_prefix(&OutputOutcomeKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_outcomes = outcomes.len();
                            ensure!(
                                num_outcomes > 0,
                                "validate_migrations was not able to read any OutputOutcomes"
                            );
                        }
                        DbKeyPrefix::MintAuditItem => {
                            let audit_items = dbtx
                                .find_by_prefix(&MintAuditItemKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_items = audit_items.len();
                            ensure!(
                                num_items > 0,
                                "validate_migrations was not able to read any MintAuditItems"
                            );
                        }
                        DbKeyPrefix::EcashBackup => {
                            let backups = dbtx
                                .find_by_prefix(&EcashBackupKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_backups = backups.len();
                            ensure!(
                                num_backups > 0,
                                "validate_migrations was not able to read any EcashBackups"
                            );
                        }
                    }
                }
                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                MintCommonGen::KIND,
                <Mint as ServerModule>::decoder(),
            )]),
        )
        .await.context("Migration validation").unwrap();
    }
}

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::iter::FromIterator;
use std::ops::Sub;

use fedimint_core::config::{
    ConfigGenParams, DkgResult, ModuleConfigResponse, ModuleGenParams, ServerModuleConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseVersion, ModuleDatabaseTransaction};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, ConsensusProposal, CoreConsensusVersion,
    ExtendsCommonModuleGen, InputMeta, IntoModuleError, ModuleConsensusVersion, ModuleError,
    PeerHandle, ServerModuleGen, TransactionItemAmount,
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
    FeeConsensus, MintConfig, MintConfigConsensus, MintConfigPrivate,
};
use fedimint_mint_common::db::{
    DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix, MintAuditItemKey,
    MintAuditItemKeyPrefix, NonceKey, NonceKeyPrefix, OutputOutcomeKey, OutputOutcomeKeyPrefix,
    ProposedPartialSignatureKey, ProposedPartialSignaturesKeyPrefix, ReceivedPartialSignatureKey,
    ReceivedPartialSignatureKeyOutputPrefix, ReceivedPartialSignaturesKeyPrefix,
};
pub use fedimint_mint_common::{BackupRequest, SignedBackupRequest};
use fedimint_mint_common::{
    BlindNonce, CombineError, MintCommonGen, MintConsensusItem, MintError, MintInput,
    MintModuleTypes, MintOutput, MintOutputBlindSignatures, MintOutputOutcome,
    MintOutputSignatureShare, MintShareErrors, Note, PeerErrorType,
    DEFAULT_MAX_NOTES_PER_DENOMINATION,
};
use fedimint_server::config::distributedgen::{scalar, PeerHandleOps};
use futures::StreamExt;
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::prelude::ParallelBridge;
use secp256k1_zkp::SECP256K1;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tbs::{
    combine_valid_shares, dealer_keygen, sign_blinded_msg, verify_blind_share, Aggregatable,
    AggregatePublicKey, PublicKeyShare, SecretKeyShare,
};
use threshold_crypto::group::Curve;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintGenParams {
    pub mint_amounts: Vec<Amount>,
}

impl ModuleGenParams for MintGenParams {
    const MODULE_NAME: &'static str = "mint";
}

#[derive(Debug, Clone)]
pub struct MintGen;

impl ExtendsCommonModuleGen for MintGen {
    type Common = MintCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleGen for MintGen {
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Mint::new(cfg.to_typed()?).into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = params.get::<MintGenParams>().expect("Invalid mint params");

        let tbs_keys = params
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
                    consensus: MintConfigConsensus {
                        peer_tbs_pks: peers
                            .iter()
                            .map(|&key_peer| {
                                let keys = params
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
        params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = params.get::<MintGenParams>().expect("Invalid mint params");

        let g2 = peers.run_dkg_multi_g2(params.mint_amounts.to_vec()).await?;

        let amounts_keys = g2
            .into_iter()
            .map(|(amount, keys)| (amount, keys.tbs()))
            .collect::<HashMap<_, _>>();

        let server = MintConfig {
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
                            .collect::<Tiered<PublicKeyShare>>();

                        (*peer, pks)
                    })
                    .collect(),
                fee_consensus: Default::default(),
                max_notes_per_denomination: DEFAULT_MAX_NOTES_PER_DENOMINATION,
            },
        };

        Ok(server.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<MintConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<MintConfig>()?.validate_config(identity)
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
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
    type VerificationCache = VerifiedNotes;

    async fn await_consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) {
        if !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            std::future::pending().await
        }
    }

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
    ) -> ConsensusProposal<MintConsensusItem> {
        ConsensusProposal::new_auto_trigger(
            dbtx.find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
                .await
                .map(|(key, signatures)| MintConsensusItem {
                    out_point: key.out_point,
                    signatures,
                })
                .collect::<Vec<MintConsensusItem>>()
                .await,
        )
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        consensus_items: Vec<(PeerId, MintConsensusItem)>,
    ) {
        for (peer, consensus_item) in consensus_items {
            self.process_partial_signature(
                dbtx,
                peer,
                consensus_item.out_point,
                consensus_item.signatures,
            )
            .await
        }
    }

    fn build_verification_cache<'a>(
        &'a self,
        inputs: impl Iterator<Item = &'a MintInput> + MaybeSend,
    ) -> Self::VerificationCache {
        // We build a lookup table for checking the validity of all notes for certain
        // amounts. This calculation can happen massively in parallel since
        // verification is a pure function and thus has no side effects.
        let iter = inputs.flat_map(|inputs| inputs.0.iter_items());

        #[cfg(not(target_family = "wasm"))]
        let iter = iter.par_bridge();

        let valid_notes = iter
            .filter_map(|(amount, note)| {
                let amount_key = self.pub_key.get(&amount)?;
                if note.verify(*amount_key) {
                    Some((*note, amount))
                } else {
                    None
                }
            })
            .collect();

        VerifiedNotes { valid_notes }
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        verification_cache: &Self::VerificationCache,
        input: &'a MintInput,
    ) -> Result<InputMeta, ModuleError> {
        for (amount, note) in input.iter_items() {
            let note_valid = verification_cache
                .valid_notes
                .get(note) // We validated the note
                .map(|notet_amount| *notet_amount == amount) // It has the right amount tier
                .unwrap_or(false); // If we didn't validate the note return false

            if !note_valid {
                return Err(MintError::InvalidSignature).into_module_error_other();
            }

            if dbtx.get_value(&NonceKey(note.0)).await.is_some() {
                return Err(MintError::SpentCoin).into_module_error_other();
            }
        }

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.total_amount(),
                fee: self.cfg.consensus.fee_consensus.note_spend_abs * (input.count_items() as u64),
            },
            puk_keys: input
                .iter_items()
                .map(|(_, note)| *note.spend_key())
                .collect(),
        })
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c, ModuleInstanceId>,
        input: &'b MintInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let meta = self
            .validate_input(interconnect, dbtx, cache, input)
            .await?;

        for (amount, note) in input.iter_items() {
            let key = NonceKey(note.0);
            dbtx.insert_new_entry(&key, &()).await;
            dbtx.insert_new_entry(&MintAuditItemKey::Redemption(key), &amount)
                .await;
        }

        Ok(meta)
    }

    async fn validate_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        output: &MintOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        if output.longest_tier_len() > self.cfg.consensus.max_notes_per_denomination.into() {
            return Err(MintError::ExceededMaxNotes(
                self.cfg.consensus.max_notes_per_denomination,
                output.longest_tier_len(),
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
            Err(MintError::InvalidAmountTier(amount)).into_module_error_other()
        } else {
            Ok(TransactionItemAmount {
                amount: output.total_amount(),
                fee: self.cfg.consensus.fee_consensus.note_issuance_abs
                    * (output.count_items() as u64),
            })
        }
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
        output: &'a MintOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        let amount = self.validate_output(dbtx, output).await?;

        // TODO: move actual signing to worker thread
        // TODO: get rid of clone
        let partial_sig = self
            .blind_sign(output.clone().0)
            .into_module_error_other()?;

        dbtx.insert_new_entry(&ProposedPartialSignatureKey { out_point }, &partial_sig)
            .await;
        dbtx.insert_new_entry(
            &MintAuditItemKey::Issuance(out_point),
            &output.total_amount(),
        )
        .await;

        Ok(amount)
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut ModuleDatabaseTransaction<'b, ModuleInstanceId>,
    ) -> Vec<PeerId> {
        struct IssuanceData {
            out_point: OutPoint,
            // TODO: remove Option, make it mandatory
            // TODO: make it only the message, remove msg from PartialSigResponse
            our_contribution: Option<MintOutputSignatureShare>,
            signature_shares: Vec<(PeerId, MintOutputSignatureShare)>,
        }

        let mut drop_peers = BTreeSet::new();

        // Finalize partial signatures for which we now have enough shares
        let issuance_requests_iter = dbtx
            .find_by_prefix(&ReceivedPartialSignaturesKeyPrefix)
            .await
            .map(|(key, partial_sig)| (key.request_id, (key.peer_id, partial_sig)))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .into_group_map()
            .into_iter();
        let mut issuance_requests = Vec::new();
        for (out_point, signature_shares) in issuance_requests_iter {
            let proposal_key = ProposedPartialSignatureKey { out_point };
            let our_contribution = dbtx.get_value(&proposal_key).await;

            issuance_requests.push(IssuanceData {
                out_point,
                our_contribution,
                signature_shares,
            });
        }

        let issuance_results = issuance_requests
            .into_par_iter()
            .map(|issuance_data| {
                let (bsig, errors) = self.combine(
                    issuance_data.our_contribution.clone(),
                    issuance_data.signature_shares.clone(),
                );
                (issuance_data, bsig, errors)
            })
            .collect::<Vec<_>>();

        for (issuance_data, bsig_res, errors) in issuance_results {
            // FIXME: validate shares before writing to DB to make combine infallible
            errors.0.iter().for_each(|(peer, error)| {
                error!("Dropping {:?} for {:?}", peer, error);
                drop_peers.insert(*peer);
            });

            match bsig_res {
                Ok(blind_signature) => {
                    debug!(
                        out_point = %issuance_data.out_point,
                        "Successfully combined signature shares",
                    );

                    for (peer, _) in issuance_data.signature_shares.into_iter() {
                        dbtx.remove_entry(&ReceivedPartialSignatureKey {
                            request_id: issuance_data.out_point,
                            peer_id: peer,
                        })
                        .await;
                    }

                    dbtx.remove_entry(&ProposedPartialSignatureKey {
                        out_point: issuance_data.out_point,
                    })
                    .await;

                    dbtx.insert_entry(&OutputOutcomeKey(issuance_data.out_point), &blind_signature)
                        .await;
                }
                Err(CombineError::TooFewShares(got, _)) => {
                    for peer in consensus_peers.sub(&HashSet::from_iter(got)) {
                        error!("Dropping {:?} for not contributing shares", peer);
                        drop_peers.insert(peer);
                    }
                }
                Err(error) => {
                    warn!(%error, "Could not combine shares");
                }
            }
        }

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

        drop_peers.into_iter().collect()
    }

    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        out_point: OutPoint,
    ) -> Option<MintOutputOutcome> {
        let we_proposed = dbtx
            .get_value(&ProposedPartialSignatureKey { out_point })
            .await
            .is_some();
        let was_consensus_outcome = dbtx
            .find_by_prefix(&ReceivedPartialSignatureKeyOutputPrefix {
                request_id: out_point,
            })
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

    async fn audit(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
        audit: &mut Audit,
    ) {
        audit
            .add_items(dbtx, &MintAuditItemKeyPrefix, |k, v| match k {
                MintAuditItemKey::Issuance(_) => -(v.msats as i64),
                MintAuditItemKey::IssuanceTotal => -(v.msats as i64),
                MintAuditItemKey::Redemption(_) => v.msats as i64,
                MintAuditItemKey::RedemptionTotal => v.msats as i64,
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "/backup",
                async |module: &Mint, dbtx, request: SignedBackupRequest| -> () {
                    module
                        .handle_backup_request(dbtx, request).await?;
                    Ok(())
                }
            },
            api_endpoint! {
                "/recover",
                async |module: &Mint, dbtx, id: secp256k1_zkp::XOnlyPublicKey| -> Option<ECashUserBackupSnapshot> {
                    Ok(module
                        .handle_recover_request(dbtx, id).await)
                }
            },
        ]
    }
}

impl Mint {
    async fn handle_backup_request(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
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
        dbtx: &mut ModuleDatabaseTransaction<'_, ModuleInstanceId>,
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
            .find_map(|(&id, pk)| if pk == &ref_pub_key { Some(id) } else { None })
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
            pub_key_shares: cfg.consensus.peer_tbs_pks,
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

    fn combine(
        &self,
        our_contribution: Option<MintOutputSignatureShare>,
        partial_sigs: Vec<(PeerId, MintOutputSignatureShare)>,
    ) -> (
        Result<MintOutputBlindSignatures, CombineError>,
        MintShareErrors,
    ) {
        // Terminate early if there are not enough shares
        if partial_sigs.len() < self.cfg.consensus.peer_tbs_pks.threshold() {
            return (
                Err(CombineError::TooFewShares(
                    partial_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                    self.cfg.consensus.peer_tbs_pks.threshold(),
                )),
                MintShareErrors(vec![]),
            );
        }

        // FIXME: decide on right boundary place for this invariant
        // Filter out duplicate contributions, they make share combinations fail
        let peer_contrib_counts = partial_sigs
            .iter()
            .map(|(idx, _)| *idx)
            .collect::<counter::Counter<_>>();
        if let Some((peer, count)) = peer_contrib_counts.into_iter().find(|(_, cnt)| *cnt > 1) {
            return (
                Err(CombineError::MultiplePeerContributions(peer, count)),
                MintShareErrors(vec![]),
            );
        }

        // Determine the reference response to check against
        let our_contribution = match our_contribution {
            Some(psig) => psig,
            None => {
                return (
                    Err(CombineError::NoOwnContribution),
                    MintShareErrors(vec![]),
                )
            }
        };

        let reference_msgs = our_contribution
            .0
            .iter_items()
            .map(|(_amt, (msg, _sig))| msg);

        let mut peer_errors = vec![];

        let partial_sigs = partial_sigs
            .iter()
            .filter(|(peer, sigs)| {
                if !sigs.0.structural_eq(&our_contribution.0) {
                    warn!(
                        %peer,
                        "Peer proposed a sig share of wrong structure (different than ours)",
                    );
                    peer_errors.push((*peer, PeerErrorType::DifferentStructureSigShare));
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();
        debug!(
            "After length filtering {} sig shares are left.",
            partial_sigs.len()
        );

        let bsigs = TieredMultiZip::new(
            partial_sigs
                .iter()
                .map(|(_peer, sig_share)| sig_share.0.iter_items())
                .collect(),
        )
        .zip(reference_msgs)
        .map(|((amt, sig_shares), ref_msg)| {
            let peer_ids = partial_sigs.iter().map(|(peer, _)| *peer);

            // Filter out invalid peer contributions
            let valid_sigs = sig_shares
                .into_iter()
                .zip(peer_ids)
                .filter_map(|((msg, sig), peer)| {
                    let amount_key = match self.pub_key_shares[&peer].tier(&amt) {
                        Ok(key) => key,
                        Err(_) => {
                            peer_errors.push((peer, PeerErrorType::InvalidAmountTier));
                            return None;
                        }
                    };

                    if msg != ref_msg {
                        peer_errors.push((peer, PeerErrorType::DifferentNonce));
                        None
                    } else if !verify_blind_share(*msg, *sig, *amount_key) {
                        peer_errors.push((peer, PeerErrorType::InvalidSignature));
                        None
                    } else {
                        Some((peer, *sig))
                    }
                })
                .collect::<Vec<_>>();

            // Check that there are still sufficient
            if valid_sigs.len() < self.cfg.consensus.peer_tbs_pks.threshold() {
                return Err(CombineError::TooFewValidShares(
                    valid_sigs.len(),
                    partial_sigs.len(),
                    self.cfg.consensus.peer_tbs_pks.threshold(),
                ));
            }

            let sig = combine_valid_shares(
                valid_sigs
                    .into_iter()
                    .map(|(peer, share)| (peer.to_usize(), share)),
                self.cfg.consensus.peer_tbs_pks.threshold(),
            );

            Ok((amt, sig))
        })
        .collect::<Result<TieredMulti<_>, CombineError>>();

        let bsigs = match bsigs {
            Ok(bs) => bs,
            Err(e) => return (Err(e), MintShareErrors(peer_errors)),
        };

        (
            Ok(MintOutputBlindSignatures(bsigs)),
            MintShareErrors(peer_errors),
        )
    }

    async fn process_partial_signature<'a>(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'a, ModuleInstanceId>,
        peer: PeerId,
        output_id: OutPoint,
        partial_sig: MintOutputSignatureShare,
    ) {
        if dbtx.get_value(&OutputOutcomeKey(output_id)).await.is_some() {
            debug!(
                issuance = %output_id,
                "Received sig share for finalized issuance, ignoring",
            );
            return;
        }

        debug!(
            %peer,
            issuance = %output_id,
            "Received sig share"
        );
        dbtx.insert_new_entry(
            &ReceivedPartialSignatureKey {
                request_id: output_id,
                peer_id: peer,
            },
            &partial_sig,
        )
        .await;
    }
}

#[cfg(test)]
mod test {
    use fedimint_core::config::{
        ClientModuleConfig, ConfigGenParams, ServerModuleConfig, TypedServerModuleConsensusConfig,
    };
    use fedimint_core::module::ServerModuleGen;
    use fedimint_core::{Amount, PeerId, TieredMulti};
    use fedimint_mint_common::config::{FeeConsensus, MintClientConfig};
    use tbs::{blind_message, unblind_signature, verify, AggregatePublicKey, BlindingKey, Message};

    use crate::{
        BlindNonce, CombineError, Mint, MintConfig, MintConfigConsensus, MintConfigPrivate,
        MintGen, MintGenParams, PeerErrorType,
    };

    const THRESHOLD: usize = 1;
    const MINTS: usize = 5;

    fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let mint_cfg = MintGen.trusted_dealer_gen(
            &peers,
            &ConfigGenParams::new().attach(MintGenParams {
                mint_amounts: vec![Amount::from_sats(1)],
            }),
        );
        let client_cfg = mint_cfg[&PeerId::from(0)]
            .to_typed::<MintConfig>()
            .unwrap()
            .consensus
            .to_client_config();

        (mint_cfg.into_values().collect(), client_cfg)
    }

    fn build_mints() -> (AggregatePublicKey, Vec<Mint>) {
        let (mint_cfg, client_cfg) = build_configs();
        let mints = mint_cfg
            .into_iter()
            .map(|config| Mint::new(config.to_typed().unwrap()))
            .collect::<Vec<_>>();

        let agg_pk = *client_cfg
            .cast::<MintClientConfig>()
            .unwrap()
            .tbs_pks
            .get(Amount::from_sats(1))
            .unwrap();

        (agg_pk, mints)
    }

    #[test_log::test]
    fn test_issuance() {
        let (pk, mut mints) = build_mints();

        let nonce = Message::from_bytes(&b"test note"[..]);
        let bkey = BlindingKey::random();
        let bmsg = blind_message(nonce, bkey);
        let blind_notes = TieredMulti::new(
            vec![(
                Amount::from_sats(1),
                vec![BlindNonce(bmsg), BlindNonce(bmsg)],
            )]
            .into_iter()
            .collect(),
        );

        let psigs = mints
            .iter()
            .enumerate()
            .map(move |(id, m)| {
                (
                    PeerId::from(id as u16),
                    m.blind_sign(blind_notes.clone()).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let our_sig = psigs[0].1.clone();
        let mint = &mut mints[0];

        // Test happy path
        let (bsig_res, errors) = mint.combine(Some(our_sig.clone()), psigs.clone());
        assert!(errors.0.is_empty());

        let bsig = bsig_res.unwrap();
        assert_eq!(bsig.0.total_amount(), Amount::from_sats(2));

        bsig.0.iter_items().for_each(|(_, bs)| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test threshold sig shares
        let (bsig_res, errors) =
            mint.combine(Some(our_sig.clone()), psigs[..(MINTS - THRESHOLD)].to_vec());
        assert!(bsig_res.is_ok());
        assert!(errors.0.is_empty());

        bsig_res.unwrap().0.iter_items().for_each(|(_, bs)| {
            let sig = unblind_signature(bkey, *bs);
            assert!(verify(nonce, sig, pk));
        });

        // Test too few sig shares
        let few_sigs = psigs[..(MINTS - THRESHOLD - 1)].to_vec();
        let (bsig_res, errors) = mint.combine(Some(our_sig.clone()), few_sigs.clone());
        assert_eq!(
            bsig_res,
            Err(CombineError::TooFewShares(
                few_sigs.iter().map(|(peer, _)| peer).cloned().collect(),
                MINTS - THRESHOLD
            ))
        );
        assert!(errors.0.is_empty());

        // Test no own share
        let (bsig_res, errors) = mint.combine(None, psigs[1..].to_vec());
        assert_eq!(bsig_res, Err(CombineError::NoOwnContribution));
        assert!(errors.0.is_empty());

        // Test multiple peer contributions
        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .chain(std::iter::once(psigs[0].clone()))
                .collect(),
        );
        assert_eq!(
            bsig_res,
            Err(CombineError::MultiplePeerContributions(PeerId::from(0), 2))
        );
        assert!(errors.0.is_empty());

        // Test wrong length response
        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psigs)| {
                    if peer == PeerId::from(1) {
                        psigs.0.get_mut(Amount::from_sats(1)).unwrap().pop();
                    }
                    (peer, psigs)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(1), PeerErrorType::DifferentStructureSigShare)));

        let (bsig_res, errors) = mint.combine(
            Some(our_sig.clone()),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(2) {
                        psig.0.get_mut(Amount::from_sats(1)).unwrap()[0].1 =
                            psigs[0].1 .0.get(Amount::from_sats(1)).unwrap()[0].1;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(2), PeerErrorType::InvalidSignature)));

        let bmsg = blind_message(Message::from_bytes(b"test"), BlindingKey::random());
        let (bsig_res, errors) = mint.combine(
            Some(our_sig),
            psigs
                .iter()
                .cloned()
                .map(|(peer, mut psig)| {
                    if peer == PeerId::from(3) {
                        psig.0.get_mut(Amount::from_sats(1)).unwrap()[0].0 = bmsg;
                    }
                    (peer, psig)
                })
                .collect(),
        );
        assert!(bsig_res.is_ok());
        assert!(errors
            .0
            .contains(&(PeerId::from(3), PeerErrorType::DifferentNonce)));
    }

    #[test_log::test]
    #[should_panic(expected = "Own key not found among pub keys.")]
    fn test_new_panic_without_own_pub_key() {
        let (mint_server_cfg1, _) = build_configs();
        let (mint_server_cfg2, _) = build_configs();

        Mint::new(MintConfig {
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
}

#[derive(Debug, Clone)]
pub struct VerifiedNotes {
    valid_notes: HashMap<Note, Amount>,
}

impl fedimint_core::server::VerificationCache for VerifiedNotes {}

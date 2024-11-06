#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

pub mod db;
mod metrics;

use std::collections::{BTreeMap, HashMap};

use anyhow::bail;
use fedimint_core::bitcoin_migration::bitcoin32_to_bitcoin30_secp256k1_pubkey;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_key_items, push_db_pair_items,
    secp256k1_29 as secp256k1, Amount, NumPeersExt, OutPoint, PeerId, ServerModule, Tiered,
    TieredMulti,
};
use fedimint_logging::LOG_MODULE_MINT;
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::{
    MintClientConfig, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate,
    MintGenParams,
};
use fedimint_mint_common::endpoint_constants::{BACKUP_ENDPOINT, RECOVER_ENDPOINT};
pub use fedimint_mint_common::{BackupRequest, SignedBackupRequest};
use fedimint_mint_common::{
    MintCommonInit, MintConsensusItem, MintInput, MintInputError, MintModuleTypes, MintOutput,
    MintOutputError, MintOutputOutcome, DEFAULT_MAX_NOTES_PER_DENOMINATION,
    MODULE_CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::{evaluate_polynomial_g2, scalar, PeerHandleOps};
use futures::StreamExt;
use itertools::Itertools;
use metrics::{
    MINT_INOUT_FEES_SATS, MINT_INOUT_SATS, MINT_ISSUED_ECASH_FEES_SATS, MINT_ISSUED_ECASH_SATS,
    MINT_REDEEMED_ECASH_FEES_SATS, MINT_REDEEMED_ECASH_SATS,
};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tbs::{
    aggregate_public_key_shares, sign_blinded_msg, AggregatePublicKey, PublicKeyShare,
    SecretKeyShare,
};
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G2Projective, Scalar};
use tracing::{debug, info};

use crate::db::{
    DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix, MintAuditItemKey,
    MintAuditItemKeyPrefix, MintOutputOutcomeKey, MintOutputOutcomePrefix, NonceKey,
    NonceKeyPrefix,
};

#[derive(Debug, Clone)]
pub struct MintInit;

impl ModuleInit for MintInit {
    type Common = MintCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
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
                        MintOutputOutcomePrefix,
                        OutputOutcomeKey,
                        MintOutputOutcome,
                        mint,
                        "Output Outcomes"
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

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for MintInit {
    type Params = MintGenParams;

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
        Ok(Mint::new(args.cfg().to_typed()?).into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let tbs_keys = params
            .consensus
            .gen_denominations()
            .iter()
            .map(|&amount| {
                let (tbs_pk, tbs_pks, tbs_sks) =
                    dealer_keygen(peers.to_num_peers().threshold(), peers.len());
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
                                    .gen_denominations()
                                    .iter()
                                    .map(|amount| {
                                        (*amount, tbs_keys[amount].1[key_peer.to_usize()])
                                    })
                                    .collect();
                                (key_peer, keys)
                            })
                            .collect(),
                        fee_consensus: params.consensus.fee_consensus(),
                        max_notes_per_denomination: DEFAULT_MAX_NOTES_PER_DENOMINATION,
                    },
                    private: MintConfigPrivate {
                        tbs_sks: params
                            .consensus
                            .gen_denominations()
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
            .run_dkg_multi_g2(params.consensus.gen_denominations())
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
                                (
                                    *amount,
                                    PublicKeyShare(evaluate_polynomial_g2(pks, &scalar(peer))),
                                )
                            })
                            .collect::<Tiered<_>>();

                        (*peer, pks)
                    })
                    .collect(),
                fee_consensus: params.consensus.fee_consensus(),
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
        // TODO: the aggregate pks should become part of the MintConfigConsensus as they
        // can be obtained by evaluating the polynomial returned by the DKG at
        // zero
        let tbs_pks =
            TieredMulti::new_aggregate_from_tiered_iter(config.peer_tbs_pks.values().cloned())
                .into_iter()
                .map(|(amt, keys)| {
                    let keys = (1_u64..)
                        .zip(keys)
                        .take(config.peer_tbs_pks.to_num_peers().threshold())
                        .collect();

                    (amt, aggregate_public_key_shares(&keys))
                })
                .collect();

        Ok(MintClientConfig {
            tbs_pks,
            fee_consensus: config.fee_consensus.clone(),
            peer_tbs_pks: config.peer_tbs_pks.clone(),
            max_notes_per_denomination: config.max_notes_per_denomination,
        })
    }
}

fn dealer_keygen(
    threshold: usize,
    keys: usize,
) -> (AggregatePublicKey, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
    let mut rng = OsRng; // FIXME: pass rng
    let poly: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();

    let apk = (G2Projective::generator() * eval_polynomial(&poly, &Scalar::zero())).to_affine();

    let sks: Vec<SecretKeyShare> = (0..keys)
        .map(|idx| SecretKeyShare(eval_polynomial(&poly, &Scalar::from(idx as u64 + 1))))
        .collect();

    let pks = sks
        .iter()
        .map(|sk| PublicKeyShare((G2Projective::generator() * sk.0).to_affine()))
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

/// Federated mint member mint
#[derive(Debug)]
pub struct Mint {
    cfg: MintConfig,
    sec_key: Tiered<SecretKeyShare>,
    pub_key: HashMap<Amount, AggregatePublicKey>,
}
#[apply(async_trait_maybe_send!)]
impl ServerModule for Mint {
    type Common = MintModuleTypes;
    type Init = MintInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<MintConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: MintConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("Mint does not process consensus items");
    }

    fn verify_input(&self, input: &MintInput) -> Result<(), MintInputError> {
        let input = input.ensure_v0_ref()?;

        let amount_key = self
            .pub_key
            .get(&input.amount)
            .ok_or(MintInputError::InvalidAmountTier(input.amount))?;

        if !input.note.verify(*amount_key) {
            return Err(MintInputError::InvalidSignature);
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b MintInput,
    ) -> Result<InputMeta, MintInputError> {
        let input = input.ensure_v0_ref()?;

        debug!(target: LOG_MODULE_MINT, nonce=%(input.note.nonce), "Marking note as spent");

        if dbtx
            .insert_entry(&NonceKey(input.note.nonce), &())
            .await
            .is_some()
        {
            return Err(MintInputError::SpentCoin);
        }

        dbtx.insert_new_entry(
            &MintAuditItemKey::Redemption(NonceKey(input.note.nonce)),
            &input.amount,
        )
        .await;

        let amount = input.amount;
        let fee = self.cfg.consensus.fee_consensus.fee(amount);

        calculate_mint_redeemed_ecash_metrics(dbtx, amount, fee);

        Ok(InputMeta {
            amount: TransactionItemAmount { amount, fee },
            pub_key: *input.note.spend_key(),
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, MintOutputError> {
        let output = output.ensure_v0_ref()?;

        let amount_key = self
            .sec_key
            .get(output.amount)
            .ok_or(MintOutputError::InvalidAmountTier(output.amount))?;

        dbtx.insert_new_entry(
            &MintOutputOutcomeKey(out_point),
            &MintOutputOutcome::new_v0(sign_blinded_msg(output.blind_nonce.0, *amount_key)),
        )
        .await;

        dbtx.insert_new_entry(&MintAuditItemKey::Issuance(out_point), &output.amount)
            .await;

        let amount = output.amount;
        let fee = self.cfg.consensus.fee_consensus.fee(amount);

        calculate_mint_issued_ecash_metrics(dbtx, amount, fee);

        Ok(TransactionItemAmount { amount, fee })
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<MintOutputOutcome> {
        dbtx.get_value(&MintOutputOutcomeKey(out_point)).await
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        let mut redemptions = Amount::from_sats(0);
        let mut issuances = Amount::from_sats(0);
        let remove_audit_keys = dbtx
            .find_by_prefix(&MintAuditItemKeyPrefix)
            .await
            .map(|(key, amount)| {
                match key {
                    MintAuditItemKey::Issuance(_) | MintAuditItemKey::IssuanceTotal => {
                        issuances += amount;
                    }
                    MintAuditItemKey::Redemption(_) | MintAuditItemKey::RedemptionTotal => {
                        redemptions += amount;
                    }
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

        audit
            .add_items(
                dbtx,
                module_instance_id,
                &MintAuditItemKeyPrefix,
                |k, v| match k {
                    MintAuditItemKey::Issuance(_) | MintAuditItemKey::IssuanceTotal => {
                        -(v.msats as i64)
                    }
                    MintAuditItemKey::Redemption(_) | MintAuditItemKey::RedemptionTotal => {
                        v.msats as i64
                    }
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                BACKUP_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Mint, context, request: SignedBackupRequest| -> () {
                    module
                        .handle_backup_request(&mut context.dbtx().into_nc(), request).await?;
                    Ok(())
                }
            },
            api_endpoint! {
                RECOVER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Mint, context, id: secp256k1::PublicKey| -> Option<ECashUserBackupSnapshot> {
                    Ok(module
                        .handle_recover_request(&mut context.dbtx().into_nc(), id).await)
                }
            },
        ]
    }
}

impl Mint {
    async fn handle_backup_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: SignedBackupRequest,
    ) -> Result<(), ApiError> {
        let request = request
            .verify_valid(secp256k1::SECP256K1)
            .map_err(|_| ApiError::bad_request("invalid request".into()))?;

        debug!(id = %request.id, len = request.payload.len(), "Received user e-cash backup request");
        if let Some(prev) = dbtx
            .get_value(&EcashBackupKey(bitcoin32_to_bitcoin30_secp256k1_pubkey(
                &request.id,
            )))
            .await
        {
            if request.timestamp <= prev.timestamp {
                debug!(id = %request.id, len = request.payload.len(), "Received user e-cash backup request with old timestamp - ignoring");
                return Err(ApiError::bad_request("timestamp too small".into()));
            }
        }

        info!(id = %request.id, len = request.payload.len(), "Storing new user e-cash backup");
        dbtx.insert_entry(
            &EcashBackupKey(bitcoin32_to_bitcoin30_secp256k1_pubkey(&request.id)),
            &ECashUserBackupSnapshot {
                timestamp: request.timestamp,
                data: request.payload.clone(),
            },
        )
        .await;

        Ok(())
    }

    async fn handle_recover_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        id: secp256k1::PublicKey,
    ) -> Option<ECashUserBackupSnapshot> {
        dbtx.get_value(&EcashBackupKey(bitcoin32_to_bitcoin30_secp256k1_pubkey(
            &id,
        )))
        .await
    }
}

fn calculate_mint_issued_ecash_metrics(
    dbtx: &mut DatabaseTransaction<'_>,
    amount: Amount,
    fee: Amount,
) {
    dbtx.on_commit(move || {
        MINT_INOUT_SATS
            .with_label_values(&["outgoing"])
            .observe(amount.sats_f64());
        MINT_INOUT_FEES_SATS
            .with_label_values(&["outgoing"])
            .observe(fee.sats_f64());
        MINT_ISSUED_ECASH_SATS.observe(amount.sats_f64());
        MINT_ISSUED_ECASH_FEES_SATS.observe(fee.sats_f64());
    });
}

fn calculate_mint_redeemed_ecash_metrics(
    dbtx: &mut DatabaseTransaction<'_>,
    amount: Amount,
    fee: Amount,
) {
    dbtx.on_commit(move || {
        MINT_INOUT_SATS
            .with_label_values(&["incoming"])
            .observe(amount.sats_f64());
        MINT_INOUT_FEES_SATS
            .with_label_values(&["incoming"])
            .observe(fee.sats_f64());
        MINT_REDEEMED_ECASH_SATS.observe(amount.sats_f64());
        MINT_REDEEMED_ECASH_FEES_SATS.observe(fee.sats_f64());
    });
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

        let ref_pub_key = cfg
            .private
            .tbs_sks
            .iter()
            .map(|(amt, key)| (amt, key.to_pub_key_share()))
            .collect();

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

        // TODO: the aggregate pks should become part of the MintConfigConsensus as they
        // can be obtained by evaluating the polynomial returned by the DKG at
        // zero
        let aggregate_pub_keys = TieredMulti::new_aggregate_from_tiered_iter(
            cfg.consensus.peer_tbs_pks.values().cloned(),
        )
        .into_iter()
        .map(|(amt, keys)| {
            let keys = (1_u64..)
                .zip(keys)
                .take(cfg.consensus.peer_tbs_pks.to_num_peers().threshold())
                .collect();

            (amt, aggregate_public_key_shares(&keys))
        })
        .collect();

        Mint {
            cfg: cfg.clone(),
            sec_key: cfg.private.tbs_sks,
            pub_key: aggregate_pub_keys,
        }
    }

    pub fn pub_key(&self) -> HashMap<Amount, AggregatePublicKey> {
        self.pub_key.clone()
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use fedimint_core::config::{
        ClientModuleConfig, ConfigGenModuleParams, EmptyGenParams, ServerModuleConfig,
    };
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleRegistry;
    use fedimint_core::module::{ModuleConsensusVersion, ServerModuleInit};
    use fedimint_core::{secp256k1, Amount, PeerId, ServerModule};
    use fedimint_mint_common::config::FeeConsensus;
    use fedimint_mint_common::{MintInput, Nonce, Note};
    use tbs::blind_message;

    use crate::common::config::MintGenParamsConsensus;
    use crate::{
        Mint, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate, MintGenParams,
        MintInit,
    };

    const MINTS: u16 = 5;

    fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
        let peers = (0..MINTS).map(PeerId::from).collect::<Vec<_>>();
        let mint_cfg = MintInit.trusted_dealer_gen(
            &peers,
            &ConfigGenModuleParams::from_typed(MintGenParams {
                local: EmptyGenParams::default(),
                consensus: MintGenParamsConsensus::new(
                    2,
                    FeeConsensus::new(1000).expect("Relative fee is within range"),
                ),
            })
            .unwrap(),
        );
        let client_cfg = ClientModuleConfig::from_typed(
            0,
            MintInit::kind(),
            ModuleConsensusVersion::new(0, 0),
            MintInit
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
                fee_consensus: FeeConsensus::new(1000).expect("Relative fee is within range"),
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
        let nonce = Nonce(note_key.public_key());
        let message = nonce.to_message();
        let blinding_key = tbs::BlindingKey::random();
        let blind_msg = blind_message(message, blinding_key);

        let bsig_shares = (1_u64..)
            .zip(server_cfgs.iter().map(|cfg| {
                let sks = *cfg
                    .to_typed::<MintConfig>()
                    .unwrap()
                    .private
                    .tbs_sks
                    .get(denomination)
                    .expect("Mint cannot issue a note of this denomination");
                tbs::sign_blinded_msg(blind_msg, sks)
            }))
            .take(server_cfgs.len() - ((server_cfgs.len() - 1) / 3))
            .collect();

        let blind_signature = tbs::aggregate_signature_shares(&bsig_shares);
        let signature = tbs::unblind_signature(blinding_key, blind_signature);

        (note_key, Note { nonce, signature })
    }

    #[test_log::test(tokio::test)]
    async fn test_detect_double_spends() {
        let (mint_server_cfg, _) = build_configs();
        let mint = Mint::new(mint_server_cfg[0].to_typed().unwrap());
        let (_, tiered) = mint
            .cfg
            .consensus
            .peer_tbs_pks
            .first_key_value()
            .expect("mint has peers");
        let highest_denomination = *tiered.max_tier();
        let (_, note) = issue_note(&mint_server_cfg, highest_denomination);

        // Normal spend works
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let input = MintInput::new_v0(highest_denomination, note);

        // Double spend in same session is detected
        let mut dbtx = db.begin_transaction_nc().await;
        mint.process_input(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &input,
        )
        .await
        .expect("Spend of valid e-cash works");
        assert_matches!(
            mint.process_input(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &input,
            )
            .await,
            Err(_)
        );
    }
}

#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

pub mod db;
mod metrics;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::bail;
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmount,
    api_endpoint,
};
use fedimint_core::{
    Amount, InPoint, NumPeersExt, OutPoint, PeerId, Tiered, TieredMulti, apply,
    async_trait_maybe_send, push_db_key_items, push_db_pair_items,
};
use fedimint_logging::LOG_MODULE_MINT;
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::{
    MintClientConfig, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate,
    MintGenParams,
};
pub use fedimint_mint_common::{BackupRequest, SignedBackupRequest};
use fedimint_mint_common::{
    DEFAULT_MAX_NOTES_PER_DENOMINATION, MODULE_CONSENSUS_VERSION, MintCommonInit,
    MintConsensusItem, MintInput, MintInputError, MintModuleTypes, MintOutput, MintOutputError,
    MintOutputOutcome,
};
use fedimint_server_core::config::{PeerHandleOps, eval_poly_g2};
use fedimint_server_core::migration::{
    ModuleHistoryItem, ServerModuleDbMigrationFn, ServerModuleDbMigrationFnContext,
    ServerModuleDbMigrationFnContextExt as _,
};
use fedimint_server_core::{ServerModule, ServerModuleInit, ServerModuleInitArgs};
use futures::{FutureExt as _, StreamExt};
use itertools::Itertools;
use metrics::{
    MINT_INOUT_FEES_SATS, MINT_INOUT_SATS, MINT_ISSUED_ECASH_FEES_SATS, MINT_ISSUED_ECASH_SATS,
    MINT_REDEEMED_ECASH_FEES_SATS, MINT_REDEEMED_ECASH_SATS,
};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tbs::{
    AggregatePublicKey, PublicKeyShare, SecretKeyShare, aggregate_public_key_shares,
    derive_pk_share, sign_message,
};
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G2Projective, Scalar};
use tracing::{debug, info, warn};

use crate::common::endpoint_constants::{BLIND_NONCE_USED_ENDPOINT, NOTE_SPENT_ENDPOINT};
use crate::common::{BlindNonce, Nonce};
use crate::db::{
    BlindNonceKey, BlindNonceKeyPrefix, DbKeyPrefix, MintAuditItemKey, MintAuditItemKeyPrefix,
    MintOutputOutcomeKey, MintOutputOutcomePrefix, NonceKey, NonceKeyPrefix,
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
                DbKeyPrefix::BlindNonce => {
                    push_db_key_items!(
                        dbtx,
                        BlindNonceKeyPrefix,
                        BlindNonceKey,
                        mint,
                        "Used Blind Nonces"
                    );
                }
            }
        }

        Box::new(mint.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for MintInit {
    type Module = Mint;
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
            &[(0, 1)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Mint::new(args.cfg().to_typed()?))
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
        peers: &(dyn PeerHandleOps + Send + Sync),
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        let mut amount_keys = HashMap::new();

        for amount in params.consensus.gen_denominations() {
            amount_keys.insert(amount, peers.run_dkg_g2().await?);
        }

        let server = MintConfig {
            local: MintConfigLocal,
            private: MintConfigPrivate {
                tbs_sks: amount_keys
                    .iter()
                    .map(|(amount, (_, sks))| (*amount, tbs::SecretKeyShare(*sks)))
                    .collect(),
            },
            consensus: MintConfigConsensus {
                peer_tbs_pks: peers
                    .num_peers()
                    .peer_ids()
                    .map(|peer| {
                        let pks = amount_keys
                            .iter()
                            .map(|(amount, (pks, _))| {
                                (*amount, PublicKeyShare(eval_poly_g2(pks, &peer)))
                            })
                            .collect::<Tiered<_>>();

                        (peer, pks)
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
            .map(|(amount, sk)| (amount, derive_pk_share(sk)))
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
                    let keys = (0_u64..)
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

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Mint>> {
        let mut migrations: BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<_>> =
            BTreeMap::new();
        migrations.insert(
            DatabaseVersion(0),
            Box::new(|ctx| migrate_db_v0(ctx).boxed()),
        );
        migrations.insert(
            DatabaseVersion(1),
            Box::new(|ctx| migrate_db_v1(ctx).boxed()),
        );
        migrations
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

async fn migrate_db_v0(
    mut migration_context: ServerModuleDbMigrationFnContext<'_, Mint>,
) -> anyhow::Result<()> {
    let blind_nonces = migration_context
        .get_typed_module_history_stream()
        .await
        .filter_map(|history_item: ModuleHistoryItem<_>| async move {
            match history_item {
                ModuleHistoryItem::Output(mint_output) => Some(
                    mint_output
                        .ensure_v0_ref()
                        .expect("This migration only runs while we only have v0 outputs")
                        .blind_nonce,
                ),
                _ => {
                    // We only care about e-cash issuances for this migration
                    None
                }
            }
        })
        .collect::<Vec<_>>()
        .await;

    info!(target: LOG_MODULE_MINT, "Found {} blind nonces in history", blind_nonces.len());

    let mut double_issuances = 0usize;
    for blind_nonce in blind_nonces {
        if migration_context
            .dbtx()
            .insert_entry(&BlindNonceKey(blind_nonce), &())
            .await
            .is_some()
        {
            double_issuances += 1;
            debug!(
                target: LOG_MODULE_MINT,
                ?blind_nonce,
                "Blind nonce already used, money was burned!"
            );
        }
    }

    if double_issuances > 0 {
        warn!(target: LOG_MODULE_MINT, "{double_issuances} blind nonces were reused, money was burned by faulty user clients!");
    }

    Ok(())
}

// Remove now unused ECash backups from DB. Backup functionality moved to core.
async fn migrate_db_v1(
    mut migration_context: ServerModuleDbMigrationFnContext<'_, Mint>,
) -> anyhow::Result<()> {
    migration_context
        .dbtx()
        .raw_remove_by_prefix(&[0x15])
        .await
        .expect("DB error");
    Ok(())
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
        _in_point: InPoint,
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
            &MintOutputOutcome::new_v0(sign_message(output.blind_nonce.0, *amount_key)),
        )
        .await;

        dbtx.insert_new_entry(&MintAuditItemKey::Issuance(out_point), &output.amount)
            .await;

        if dbtx
            .insert_entry(&BlindNonceKey(output.blind_nonce), &())
            .await
            .is_some()
        {
            // TODO: make a consensus rule against this
            warn!(
                target: LOG_MODULE_MINT,
                denomination = %output.amount,
                bnonce = ?output.blind_nonce,
                "Blind nonce already used, money was burned!"
            );
        }

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

    #[doc(hidden)]
    async fn verify_output_submission<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        _out_point: OutPoint,
    ) -> Result<(), MintOutputError> {
        let output = output.ensure_v0_ref()?;

        if dbtx
            .get_value(&BlindNonceKey(output.blind_nonce))
            .await
            .is_some()
        {
            return Err(MintOutputError::BlindNonceAlreadyUsed);
        }

        Ok(())
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
                NOTE_SPENT_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, nonce: Nonce| -> bool {
                    Ok(context.dbtx().get_value(&NonceKey(nonce)).await.is_some())
                }
            },
            api_endpoint! {
                BLIND_NONCE_USED_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, blind_nonce: BlindNonce| -> bool {
                    Ok(context.dbtx().get_value(&BlindNonceKey(blind_nonce)).await.is_some())
                }
            },
        ]
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
        assert!(
            cfg.consensus
                .peer_tbs_pks
                .values()
                .all(|pk| pk.structural_eq(&cfg.private.tbs_sks))
        );

        let ref_pub_key = cfg
            .private
            .tbs_sks
            .iter()
            .map(|(amount, sk)| (amount, derive_pk_share(sk)))
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
                .map(|(amount, sk)| (amount, derive_pk_share(sk)))
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
            let keys = (0_u64..)
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
mod test;

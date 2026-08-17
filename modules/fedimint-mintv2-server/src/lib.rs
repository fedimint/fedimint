#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

pub mod db;

use std::collections::BTreeMap;

use anyhow::{bail, ensure};
use bitcoin::hashes::sha256;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::envs::{FM_ENABLE_MODULE_MINTV2_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    AmountUnit, Amounts, ApiEndpoint, ApiError, ApiVersion, CommonModuleInit, CoreConsensusVersion,
    InputMeta, ModuleConsensusVersion, ModuleInit, TransactionItemAmounts, public_api_endpoint,
};
use fedimint_core::{
    Amount, BitcoinHash, InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, apply,
    async_trait_maybe_send, push_db_key_items, push_db_pair_items,
};
use fedimint_mintv2_common::config::{
    FeeConsensus, MintClientConfig, MintConfig, MintConfigConsensus, MintConfigPrivate,
    consensus_denominations,
};
use fedimint_mintv2_common::endpoint_constants::{
    RECOVERY_COUNT_ENDPOINT, RECOVERY_SLICE_ENDPOINT, RECOVERY_SLICE_HASH_ENDPOINT,
    SIGNATURE_SHARES_ENDPOINT, SIGNATURE_SHARES_RECOVERY_ENDPOINT,
};
use fedimint_mintv2_common::{
    Denomination, MODULE_CONSENSUS_VERSION, MintCommonInit, MintConsensusItem, MintInput,
    MintInputError, MintModuleTypes, MintOutput, MintOutputError, MintOutputOutcome, RecoveryItem,
    verify_note,
};
use fedimint_server_core::config::{
    FM_ALLOW_COMPROMISED_MODULE_KEYS_ENV, PeerHandleOps, ensure_uncompromised_key, eval_poly_g2,
    eval_poly_scalar, scalar,
};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use strum::IntoEnumIterator;
use tbs::{
    AggregatePublicKey, BlindedSignatureShare, PublicKeyShare, SecretKeyShare, derive_pk_share,
};
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G2Projective, Scalar};

use crate::db::{
    BlindedSignatureShareKey, BlindedSignatureSharePrefix, BlindedSignatureShareRecoveryKey,
    BlindedSignatureShareRecoveryPrefix, DbKeyPrefix, IssuanceCounterKey, IssuanceCounterPrefix,
    NonceKey, NonceKeyPrefix, RecoveryItemKey, RecoveryItemPrefix,
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
                DbKeyPrefix::BlindedSignatureShare => {
                    push_db_pair_items!(
                        dbtx,
                        BlindedSignatureSharePrefix,
                        BlindedSignatureShareKey,
                        BlindedSignatureShare,
                        mint,
                        "Blinded Signature Shares"
                    );
                }
                DbKeyPrefix::BlindedSignatureShareRecovery => {
                    push_db_pair_items!(
                        dbtx,
                        BlindedSignatureShareRecoveryPrefix,
                        BlindedSignatureShareRecoveryKey,
                        BlindedSignatureShare,
                        mint,
                        "Blinded Signature Shares (Recovery)"
                    );
                }
                DbKeyPrefix::MintAuditItem => {
                    push_db_pair_items!(
                        dbtx,
                        IssuanceCounterPrefix,
                        IssuanceCounterKey,
                        u64,
                        mint,
                        "Issuance Counter"
                    );
                }
                DbKeyPrefix::RecoveryItem => {
                    push_db_pair_items!(
                        dbtx,
                        RecoveryItemPrefix,
                        RecoveryItemKey,
                        RecoveryItem,
                        mint,
                        "Recovery Items"
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

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_MINTV2_ENV).unwrap_or(true)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![
            EnvVarDoc {
                name: FM_ENABLE_MODULE_MINTV2_ENV,
                description: "Set to 0/false to disable the MintV2 module. Enabled by default.",
            },
            EnvVarDoc {
                name: FM_ALLOW_COMPROMISED_MODULE_KEYS_ENV,
                description: "Set to 1/true to start up even though our key material is publicly \
                              known. Only ever set this to recover the funds of an affected \
                              federation.",
            },
        ]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        args.cfg().to_typed().map(|cfg| Mint {
            cfg,
            db: args.db().clone(),
        })
    }

    fn insecure_test_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let fee_consensus = if args.disable_base_fees {
            FeeConsensus::zero()
        } else {
            FeeConsensus::new(0).expect("Relative fee is within range")
        };

        let keys = consensus_denominations()
            .map(|denomination| (denomination, dealer_keygen(peers.to_num_peers())))
            .collect::<BTreeMap<Denomination, DealerKeys>>();

        let tbs_agg_pks = keys
            .iter()
            .map(|(denomination, (agg_pk, ..))| (*denomination, *agg_pk))
            .collect::<BTreeMap<Denomination, AggregatePublicKey>>();

        let tbs_pks = keys
            .iter()
            .map(|(denomination, (_, pks, _))| (*denomination, pks.clone()))
            .collect::<BTreeMap<Denomination, BTreeMap<PeerId, PublicKeyShare>>>();

        peers
            .iter()
            .map(|peer| {
                let cfg = MintConfig {
                    consensus: MintConfigConsensus {
                        tbs_agg_pks: tbs_agg_pks.clone(),
                        tbs_pks: tbs_pks.clone(),
                        fee_consensus: fee_consensus.clone(),
                        amount_unit: AmountUnit::BITCOIN,
                    },
                    private: MintConfigPrivate {
                        tbs_sks: keys
                            .iter()
                            .map(|(denomination, (_, _, sks))| (*denomination, sks[peer]))
                            .collect(),
                    },
                };

                (*peer, cfg.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let fee_consensus = if args.disable_base_fees {
            FeeConsensus::zero()
        } else {
            FeeConsensus::new(0).expect("Relative fee is within range")
        };

        let mut tbs_sks = BTreeMap::new();
        let mut tbs_agg_pks = BTreeMap::new();
        let mut tbs_pks = BTreeMap::new();

        for denomination in consensus_denominations() {
            let (poly, sk) = peers.run_dkg_g2().await?;

            tbs_sks.insert(denomination, tbs::SecretKeyShare(sk));

            tbs_agg_pks.insert(denomination, AggregatePublicKey(poly[0].to_affine()));

            let pks = peers
                .num_peers()
                .peer_ids()
                .map(|peer| (peer, PublicKeyShare(eval_poly_g2(&poly, &peer))))
                .collect();

            tbs_pks.insert(denomination, pks);
        }

        let cfg = MintConfig {
            private: MintConfigPrivate { tbs_sks },
            consensus: MintConfigConsensus {
                tbs_agg_pks,
                tbs_pks,
                fee_consensus,
                amount_unit: AmountUnit::BITCOIN,
            },
        };

        Ok(cfg.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<MintConfig>()?;

        for denomination in consensus_denominations() {
            let pk = derive_pk_share(&config.private.tbs_sks[&denomination]);

            ensure!(
                pk == config.consensus.tbs_pks[&denomination][identity],
                "Mint private key doesn't match pubkey share"
            );

            ensure_uncompromised_key(
                config.private.tbs_sks[&denomination]
                    == compromised_dealer_sk(
                        denomination.amount(),
                        config.consensus.tbs_pks[&denomination].to_num_peers(),
                        *identity,
                    ),
                MintCommonInit::KIND.as_str(),
            )?;
        }

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<MintClientConfig> {
        let config = MintConfigConsensus::from_erased(config)?;

        Ok(MintClientConfig {
            tbs_agg_pks: config.tbs_agg_pks,
            tbs_pks: config.tbs_pks.clone(),
            fee_consensus: config.fee_consensus.clone(),
            amount_unit: config.amount_unit,
        })
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Mint>> {
        BTreeMap::new()
    }
}

type DealerKeys = (
    AggregatePublicKey,
    BTreeMap<PeerId, PublicKeyShare>,
    BTreeMap<PeerId, SecretKeyShare>,
);

/// Samples a random polynomial and hands out a share of it to every peer.
///
/// This puts the aggregate secret key into a single process and is therefore
/// only used by [`MintInit::insecure_test_dealer_gen`]. The polynomial is still
/// sampled from the OS RNG - a test helper that silently produces publicly
/// known keys is exactly the trap we are fixing here.
fn dealer_keygen(num_peers: NumPeers) -> DealerKeys {
    let polynomial = (0..num_peers.threshold())
        .map(|_| Scalar::random(&mut OsRng))
        .collect::<Vec<Scalar>>();

    let constant_term = *polynomial
        .first()
        .expect("We have at least one coefficient");

    let agg_pk = AggregatePublicKey((G2Projective::generator() * constant_term).to_affine());

    let sks = num_peers
        .peer_ids()
        .map(|peer| {
            (
                peer,
                SecretKeyShare(eval_poly_scalar(&polynomial, &scalar(&peer))),
            )
        })
        .collect::<BTreeMap<PeerId, SecretKeyShare>>();

    let pks = sks
        .iter()
        .map(|(peer, sk)| (*peer, derive_pk_share(sk)))
        .collect();

    (agg_pk, pks, sks)
}

/// Recomputes the secret key share that the deterministic dealer key generation
/// used up to and including v0.12 would have produced for `peer`.
///
/// This is derived from nothing but the denomination and the peer index, so
/// anyone can recompute it. It is kept solely so that
/// [`MintInit::validate_config`] can recognise an affected federation and
/// refuse to start.
fn compromised_dealer_sk(amount: Amount, num_peers: NumPeers, peer: PeerId) -> SecretKeyShare {
    let x = Scalar::from(peer.to_usize() as u64 + 1);

    // We evaluate the scalar polynomial of degree threshold - 1 at the point x
    // using the Horner schema.

    let y = (0..num_peers.threshold())
        .map(|index| compromised_coefficient(amount, index as u64))
        .rev()
        .reduce(|accumulator, c| accumulator * x + c)
        .expect("We have at least one coefficient");

    SecretKeyShare(y)
}

fn compromised_coefficient(amount: Amount, index: u64) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(
        *(amount, index)
            .consensus_hash::<sha256::Hash>()
            .as_byte_array(),
    ))
}

#[derive(Debug)]
pub struct Mint {
    cfg: MintConfig,
    db: Database,
}

impl Mint {
    pub async fn note_distribution_ui(&self) -> BTreeMap<Denomination, u64> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&IssuanceCounterPrefix)
            .await
            .filter(|entry| std::future::ready(entry.1 > 0))
            .map(|(key, count)| (key.0, count))
            .collect()
            .await
    }
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

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b MintInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, MintInputError> {
        let input = input.ensure_v0_ref()?;

        let pk = self
            .cfg
            .consensus
            .tbs_agg_pks
            .get(&input.note.denomination)
            .ok_or(MintInputError::InvalidDenomination)?;

        if !verify_note(input.note, *pk) {
            return Err(MintInputError::InvalidSignature);
        }

        if dbtx
            .insert_entry(&NonceKey(input.note.nonce), &())
            .await
            .is_some()
        {
            return Err(MintInputError::SpentCoin);
        }

        let new_count = dbtx
            .remove_entry(&IssuanceCounterKey(input.note.denomination))
            .await
            .unwrap_or(0)
            .checked_sub(1)
            .expect("Failed to decrement issuance counter");

        dbtx.insert_new_entry(&IssuanceCounterKey(input.note.denomination), &new_count)
            .await;

        let next_index = get_recovery_count(dbtx).await;

        dbtx.insert_new_entry(
            &RecoveryItemKey(next_index),
            &RecoveryItem::Input {
                nonce_hash: input.note.nonce.consensus_hash(),
            },
        )
        .await;

        let amount = input.note.amount();
        let unit = self.cfg.consensus.amount_unit;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_custom(unit, amount),
                fees: Amounts::new_custom(unit, self.cfg.consensus.fee_consensus.fee(amount)),
            },
            pub_key: input.note.nonce,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmounts, MintOutputError> {
        let output = output.ensure_v0_ref()?;

        let signature = self
            .cfg
            .private
            .tbs_sks
            .get(&output.denomination)
            .map(|key| tbs::sign_message(output.nonce, *key))
            .ok_or(MintOutputError::InvalidDenomination)?;

        // Store by outpoint for efficient range-based retrieval
        dbtx.insert_entry(&BlindedSignatureShareKey(outpoint), &signature)
            .await;

        // Store by blinded message for recovery
        dbtx.insert_entry(&BlindedSignatureShareRecoveryKey(output.nonce), &signature)
            .await;

        let new_count = dbtx
            .remove_entry(&IssuanceCounterKey(output.denomination))
            .await
            .unwrap_or(0)
            .checked_add(1)
            .expect("Failed to increment issuance counter");

        dbtx.insert_new_entry(&IssuanceCounterKey(output.denomination), &new_count)
            .await;

        let next_index = get_recovery_count(dbtx).await;

        dbtx.insert_new_entry(
            &RecoveryItemKey(next_index),
            &RecoveryItem::Output {
                denomination: output.denomination,
                nonce_hash: output.nonce.consensus_hash(),
                tweak: output.tweak,
            },
        )
        .await;

        let amount = output.amount();
        let unit = self.cfg.consensus.amount_unit;

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_custom(unit, amount),
            fees: Amounts::new_custom(unit, self.cfg.consensus.fee_consensus.fee(amount)),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _outpoint: OutPoint,
    ) -> Option<MintOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(dbtx, module_instance_id, &IssuanceCounterPrefix, |k, v| {
                -((k.0.amount().msats * v) as i64)
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                SIGNATURE_SHARES_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: fedimint_core::OutPointRange| -> Vec<BlindedSignatureShare> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_signature_shares(&mut dbtx, range).await)
                }
            },
            public_api_endpoint! {
                SIGNATURE_SHARES_RECOVERY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, messages: Vec<tbs::BlindedMessage>| -> Vec<BlindedSignatureShare> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    get_signature_shares_recovery(&mut dbtx, messages).await
                }
            },
            public_api_endpoint! {
                RECOVERY_SLICE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: (u64, u64)| -> Vec<RecoveryItem> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_recovery_slice(&mut dbtx, range).await)
                }
            },
            public_api_endpoint! {
                RECOVERY_SLICE_HASH_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: (u64, u64)| -> bitcoin::hashes::sha256::Hash {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_recovery_slice(&mut dbtx, range).await.consensus_hash())
                }
            },
            public_api_endpoint! {
                RECOVERY_COUNT_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_recovery_count(&mut dbtx).await)
                }
            },
        ]
    }
}

async fn get_signature_shares(
    dbtx: &mut DatabaseTransaction<'_>,
    range: fedimint_core::OutPointRange,
) -> Vec<BlindedSignatureShare> {
    let start_key = BlindedSignatureShareKey(range.start_out_point());
    let end_key = BlindedSignatureShareKey(range.end_out_point());

    dbtx.find_by_range(start_key..end_key)
        .await
        .map(|entry| entry.1)
        .collect()
        .await
}

async fn get_signature_shares_recovery(
    dbtx: &mut DatabaseTransaction<'_>,
    messages: Vec<tbs::BlindedMessage>,
) -> Result<Vec<BlindedSignatureShare>, ApiError> {
    let mut shares = Vec::new();

    for message in messages {
        let share = dbtx
            .get_value(&BlindedSignatureShareRecoveryKey(message))
            .await
            .ok_or(ApiError::bad_request(
                "No blinded signature share found".to_string(),
            ))?;

        shares.push(share);
    }

    Ok(shares)
}

async fn get_recovery_count(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.find_by_prefix_sorted_descending(&RecoveryItemPrefix)
        .await
        .next()
        .await
        .map_or(0, |entry| entry.0.0 + 1)
}

async fn get_recovery_slice(
    dbtx: &mut DatabaseTransaction<'_>,
    range: (u64, u64),
) -> Vec<RecoveryItem> {
    dbtx.find_by_range(RecoveryItemKey(range.0)..RecoveryItemKey(range.1))
        .await
        .map(|entry| entry.1)
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use fedimint_core::config::TypedServerModuleConfig;
    use fedimint_core::module::AmountUnit;
    use fedimint_core::{NumPeersExt, PeerId};
    use fedimint_mintv2_common::config::{
        FeeConsensus, MintConfig, MintConfigConsensus, MintConfigPrivate, consensus_denominations,
    };
    use fedimint_server_core::{ConfigGenModuleArgs, ServerModuleInit};
    use tbs::derive_pk_share;

    use super::{MintInit, compromised_dealer_sk, dealer_keygen};

    fn args() -> ConfigGenModuleArgs {
        ConfigGenModuleArgs {
            network: bitcoin::Network::Regtest,
            disable_base_fees: false,
        }
    }

    /// Builds the config that the deterministic dealer key generation used up
    /// to and including v0.12 would have produced. It is internally consistent,
    /// so only the compromised key check can reject it.
    fn compromised_config(peers: &[PeerId], identity: PeerId) -> MintConfig {
        let num_peers = peers.to_num_peers();

        MintConfig {
            consensus: MintConfigConsensus {
                tbs_agg_pks: consensus_denominations()
                    .map(|denomination| (denomination, dealer_keygen(num_peers).0))
                    .collect(),
                tbs_pks: consensus_denominations()
                    .map(|denomination| {
                        let pks = peers
                            .iter()
                            .map(|peer| {
                                (
                                    *peer,
                                    derive_pk_share(&compromised_dealer_sk(
                                        denomination.amount(),
                                        num_peers,
                                        *peer,
                                    )),
                                )
                            })
                            .collect();

                        (denomination, pks)
                    })
                    .collect(),
                fee_consensus: FeeConsensus::new(0).expect("Relative fee is within range"),
                amount_unit: AmountUnit::BITCOIN,
            },
            private: MintConfigPrivate {
                tbs_sks: consensus_denominations()
                    .map(|denomination| {
                        (
                            denomination,
                            compromised_dealer_sk(denomination.amount(), num_peers, identity),
                        )
                    })
                    .collect(),
            },
        }
    }

    #[test]
    fn dealer_keygen_is_not_deterministic() {
        let num_peers = vec![PeerId::from(0)].to_num_peers();

        assert_ne!(dealer_keygen(num_peers).2, dealer_keygen(num_peers).2);
    }

    #[test]
    fn validate_config_accepts_freshly_generated_configs() {
        for size in [1_u16, 4] {
            let peers = (0..size).map(PeerId::from).collect::<Vec<PeerId>>();

            for (identity, config) in MintInit.insecure_test_dealer_gen(&peers, &args()) {
                MintInit
                    .validate_config(&identity, config)
                    .expect("Freshly generated config is valid");
            }
        }
    }

    #[test]
    fn validate_config_rejects_deterministic_dealer_keys() {
        for size in [1_u16, 4] {
            let peers = (0..size).map(PeerId::from).collect::<Vec<PeerId>>();

            for identity in peers.clone() {
                let error = MintInit
                    .validate_config(&identity, compromised_config(&peers, identity).to_erased())
                    .expect_err("Deterministic dealer keys have to be rejected");

                assert!(error.to_string().contains("publicly known key material"));
            }
        }
    }
}

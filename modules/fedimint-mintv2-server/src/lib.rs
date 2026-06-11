#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

mod db;

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
    AmountUnit, Amounts, ApiEndpoint, ApiError, ApiVersion, CORE_CONSENSUS_VERSION,
    CoreConsensusVersion, FeeCharge, FeeComponent, FeeConsensusSchedule, FeePriority, FeeRate,
    InputMeta, InputMetaWithFees, ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions,
    TransactionItemAmounts, TransactionItemAmountsWithFees, TransactionItemFees, api_endpoint,
};
use fedimint_core::{
    Amount, BitcoinHash, InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, apply,
    async_trait_maybe_send, push_db_key_items, push_db_pair_items,
};
use fedimint_mintv2_common::config::{
    FeeConfig, FeeConsensus as MintFeeConsensus, MintClientConfig, MintConfig, MintConfigConsensus,
    MintConfigPrivate, consensus_denominations,
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
use fedimint_server_core::config::{PeerHandleOps, eval_poly_g2};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use rand::SeedableRng;
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

const MINT_FEE_PRIORITY: FeePriority = FeePriority(0);

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

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_MINTV2_ENV).unwrap_or(false)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_MINTV2_ENV,
            description: "Set to 1/true to enable the MintV2 module (experimental). Disabled by default.",
        }]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        args.cfg().to_typed().map(|cfg| Mint {
            cfg,
            db: args.db().clone(),
        })
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let fee_consensus = if args.disable_base_fees {
            FeeConfig::zero()
        } else {
            FeeConfig::new(0).expect("Relative fee is within range")
        };

        let tbs_agg_pks = consensus_denominations()
            .map(|denomination| (denomination, dealer_agg_pk(denomination.amount())))
            .collect::<BTreeMap<Denomination, AggregatePublicKey>>();

        let tbs_pks = consensus_denominations()
            .map(|denomination| {
                let pks = peers
                    .iter()
                    .map(|peer| {
                        (
                            *peer,
                            dealer_pk(denomination.amount(), peers.to_num_peers(), *peer),
                        )
                    })
                    .collect();

                (denomination, pks)
            })
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
                        tbs_sks: consensus_denominations()
                            .map(|denomination| {
                                (
                                    denomination,
                                    dealer_sk(denomination.amount(), peers.to_num_peers(), *peer),
                                )
                            })
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
            FeeConfig::zero()
        } else {
            FeeConfig::new(0).expect("Relative fee is within range")
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

fn dealer_agg_pk(amount: Amount) -> AggregatePublicKey {
    AggregatePublicKey((G2Projective::generator() * coefficient(amount, 0)).to_affine())
}

fn dealer_pk(amount: Amount, num_peers: NumPeers, peer: PeerId) -> PublicKeyShare {
    derive_pk_share(&dealer_sk(amount, num_peers, peer))
}

fn dealer_sk(amount: Amount, num_peers: NumPeers, peer: PeerId) -> SecretKeyShare {
    let x = Scalar::from(peer.to_usize() as u64 + 1);

    // We evaluate the scalar polynomial of degree threshold - 1 at the point x
    // using the Horner schema.

    let y = (0..num_peers.threshold())
        .map(|index| coefficient(amount, index as u64))
        .rev()
        .reduce(|accumulator, c| accumulator * x + c)
        .expect("We have at least one coefficient");

    SecretKeyShare(y)
}

fn coefficient(amount: Amount, index: u64) -> Scalar {
    Scalar::random(&mut ChaChaRng::from_seed(
        *(amount, index)
            .consensus_hash::<sha256::Hash>()
            .as_byte_array(),
    ))
}

fn minimum_mint_fee_rate(
    fee_consensus: &[FeeConsensusSchedule<MintFeeConsensus>],
    select_fee_rate: impl Fn(&MintFeeConsensus) -> FeeRate,
) -> FeeRate {
    let Some(first_fee_rate) = fee_consensus
        .first()
        .map(|schedule| select_fee_rate(&schedule.fee_consensus))
    else {
        return FeeRate::zero();
    };

    fee_consensus
        .iter()
        .skip(1)
        .map(|schedule| select_fee_rate(&schedule.fee_consensus))
        .fold(first_fee_rate, |min_fee_rate, fee_rate| {
            FeeRate::new(
                min_fee_rate.base_fee().min(fee_rate.base_fee()),
                min_fee_rate
                    .parts_per_million()
                    .min(fee_rate.parts_per_million()),
            )
            .expect("minimum of valid fee rates must remain valid")
        })
}

fn mint_transaction_item_fees(
    amount_unit: AmountUnit,
    amount: Amount,
    legacy_fee: Amounts,
    fee_consensus: &[FeeConsensusSchedule<MintFeeConsensus>],
    select_fee_rate: impl Fn(&MintFeeConsensus) -> FeeRate,
) -> TransactionItemFees {
    let fee_rate = minimum_mint_fee_rate(fee_consensus, select_fee_rate);

    TransactionItemFees {
        dynamic: vec![
            FeeComponent {
                fees: Amounts::new_custom(amount_unit, fee_rate.base_fee()),
                charge: FeeCharge::Always,
            },
            FeeComponent {
                fees: Amounts::new_custom(amount_unit, fee_rate.proportional_fee(amount)),
                charge: FeeCharge::IfMaxPriority(MINT_FEE_PRIORITY),
            },
        ],
        legacy_floor: vec![FeeComponent {
            fees: legacy_fee,
            charge: FeeCharge::Always,
        }],
    }
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
    type FeeConsensus = MintFeeConsensus;
    type Init = MintInit;

    fn initial_fee_consensus(&self) -> Self::FeeConsensus {
        MintFeeConsensus::from_config(&self.cfg.consensus.fee_consensus)
            .expect("config fee consensus must be valid")
    }

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _module_consensus_version: ModuleConsensusVersion,
    ) -> Vec<MintConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: MintConsensusItem,
        _peer_id: PeerId,
        _module_consensus_version: ModuleConsensusVersion,
    ) -> anyhow::Result<()> {
        bail!("Mint does not process consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b MintInput,
        _in_point: InPoint,
        _module_consensus_version: ModuleConsensusVersion,
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

    async fn process_input_with_fees<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b MintInput,
        in_point: InPoint,
        module_consensus_version: ModuleConsensusVersion,
        fee_consensus: &[FeeConsensusSchedule<Self::FeeConsensus>],
    ) -> Result<InputMetaWithFees, MintInputError> {
        let processed = self
            .process_input(dbtx, input, in_point, module_consensus_version)
            .await?;
        let unit = self.cfg.consensus.amount_unit;
        let amount = processed
            .amount
            .amounts
            .get(&unit)
            .copied()
            .unwrap_or(Amount::ZERO);
        let fees = mint_transaction_item_fees(
            unit,
            amount,
            processed.amount.fees,
            fee_consensus,
            |fee_consensus| fee_consensus.input,
        );

        Ok(InputMetaWithFees {
            amount: TransactionItemAmountsWithFees {
                amounts: processed.amount.amounts,
                fees,
            },
            pub_key: processed.pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        outpoint: OutPoint,
        _module_consensus_version: ModuleConsensusVersion,
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

    async fn process_output_with_fees<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        outpoint: OutPoint,
        module_consensus_version: ModuleConsensusVersion,
        fee_consensus: &[FeeConsensusSchedule<Self::FeeConsensus>],
    ) -> Result<TransactionItemAmountsWithFees, MintOutputError> {
        let processed = self
            .process_output(dbtx, output, outpoint, module_consensus_version)
            .await?;
        let unit = self.cfg.consensus.amount_unit;
        let amount = processed
            .amounts
            .get(&unit)
            .copied()
            .unwrap_or(Amount::ZERO);
        let fees = mint_transaction_item_fees(
            unit,
            amount,
            processed.fees,
            fee_consensus,
            |fee_consensus| fee_consensus.output,
        );

        Ok(TransactionItemAmountsWithFees {
            amounts: processed.amounts,
            fees,
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
        _module_consensus_version: ModuleConsensusVersion,
    ) {
        audit
            .add_items(dbtx, module_instance_id, &IssuanceCounterPrefix, |k, v| {
                -((k.0.amount().msats * v) as i64)
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                SIGNATURE_SHARES_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: fedimint_core::OutPointRange| -> Vec<BlindedSignatureShare> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_signature_shares(&mut dbtx, range).await)
                }
            },
            api_endpoint! {
                SIGNATURE_SHARES_RECOVERY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, messages: Vec<tbs::BlindedMessage>| -> Vec<BlindedSignatureShare> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    get_signature_shares_recovery(&mut dbtx, messages).await
                }
            },
            api_endpoint! {
                RECOVERY_SLICE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: (u64, u64)| -> Vec<RecoveryItem> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_recovery_slice(&mut dbtx, range).await)
                }
            },
            api_endpoint! {
                RECOVERY_SLICE_HASH_ENDPOINT,
                ApiVersion::new(0, 1),
                async |_module: &Mint, context, range: (u64, u64)| -> bitcoin::hashes::sha256::Hash {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(get_recovery_slice(&mut dbtx, range).await.consensus_hash())
                }
            },
            api_endpoint! {
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

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
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    CoreMigrationFn, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_key_items, push_db_pair_items, Amount, BitcoinHash,
    NumPeers, NumPeersExt, OutPoint, PeerId, ServerModule,
};
use fedimint_mintv2_common::config::{
    consensus_denominations, MintClientConfig, MintConfig, MintConfigConsensus, MintConfigLocal,
    MintConfigPrivate, MintGenParams,
};
use fedimint_mintv2_common::endpoint_constants::SIGNATURE_SHARES_ENDPOINT;
pub use fedimint_mintv2_common::{BackupRequest, SignedBackupRequest};
use fedimint_mintv2_common::{
    MintCommonInit, MintConsensusItem, MintInput, MintInputError, MintModuleTypes, MintOutput,
    MintOutputError, MintOutputOutcome, MODULE_CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::{evaluate_polynomial_g2, scalar, PeerHandleOps};
use futures::StreamExt;
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use strum::IntoEnumIterator;
use tbs::{
    sign_blinded_msg, AggregatePublicKey, BlindedSignatureShare, PublicKeyShare, SecretKeyShare,
};
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::{G2Projective, Scalar};

use crate::db::{
    BlindedSignatureShareKey, BlindedSignatureSharePrefix, DbKeyPrefix, IssuanceCounterKey,
    IssuanceCounterPrefix, NonceKey, NonceKeyPrefix,
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
                        "Output Outcomes"
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
            &[(0, 1)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Mint {
            cfg: args.cfg().to_typed()?,
        }
        .into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self
            .parse_params(params)
            .expect("Failed to parse mintv2 config gen params");

        let tbs_agg_pks = consensus_denominations()
            .into_iter()
            .map(|amount| (amount, dealer_agg_pk(amount)))
            .collect::<BTreeMap<Amount, AggregatePublicKey>>();

        let tbs_pks = consensus_denominations()
            .into_iter()
            .map(|amount| {
                let pks = peers
                    .iter()
                    .map(|peer| (*peer, dealer_pk(amount, peers.to_num_peers(), *peer)))
                    .collect();

                (amount, pks)
            })
            .collect::<BTreeMap<Amount, BTreeMap<PeerId, PublicKeyShare>>>();

        peers
            .iter()
            .map(|peer| {
                let cfg = MintConfig {
                    local: MintConfigLocal,
                    consensus: MintConfigConsensus {
                        tbs_agg_pks: tbs_agg_pks.clone(),
                        tbs_pks: tbs_pks.clone(),
                        fee_consensus: params.consensus.fee_consensus.clone(),
                    },
                    private: MintConfigPrivate {
                        tbs_sks: consensus_denominations()
                            .into_iter()
                            .map(|amount| (amount, dealer_sk(amount, peers.to_num_peers(), *peer)))
                            .collect(),
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
    ) -> DkgResult<ServerModuleConfig> {
        let params = self
            .parse_params(params)
            .expect("Failed to parse mintv2 config gen params");

        let mut tbs_sks = BTreeMap::new();
        let mut tbs_agg_pks = BTreeMap::new();
        let mut tbs_pks = BTreeMap::new();

        for (amount, dkg_keys) in peers
            .run_dkg_multi_g2(consensus_denominations().collect())
            .await?
        {
            let (polynomial, sk) = dkg_keys.tbs();

            tbs_sks.insert(amount, sk);

            tbs_agg_pks.insert(amount, AggregatePublicKey(polynomial[0].to_affine()));

            let pks = peers
                .peer_ids()
                .iter()
                .map(|peer| {
                    let pk = PublicKeyShare(evaluate_polynomial_g2(&polynomial, &scalar(peer)));

                    (*peer, pk)
                })
                .collect();

            tbs_pks.insert(amount, pks);
        }

        let cfg = MintConfig {
            local: MintConfigLocal,
            private: MintConfigPrivate { tbs_sks },
            consensus: MintConfigConsensus {
                tbs_agg_pks,
                tbs_pks,
                fee_consensus: params.consensus.fee_consensus.clone(),
            },
        };

        Ok(cfg.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<MintConfig>()?;

        ensure!(
            config
                .private
                .tbs_sks
                .keys()
                .contains(&Amount::from_msats(1)),
            "No msat 1 denomination"
        );

        for amount in consensus_denominations() {
            let pk = config.private.tbs_sks[&amount].to_pub_key_share();

            ensure!(
                pk == config.consensus.tbs_pks[&amount][identity],
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
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        BTreeMap::new()
    }
}

fn dealer_agg_pk(amount: Amount) -> AggregatePublicKey {
    AggregatePublicKey((G2Projective::generator() * coefficient(amount, 0)).to_affine())
}

fn dealer_pk(amount: Amount, num_peers: NumPeers, peer: PeerId) -> PublicKeyShare {
    dealer_sk(amount, num_peers, peer).to_pub_key_share()
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

#[derive(Debug)]
pub struct Mint {
    cfg: MintConfig,
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
    ) -> Result<InputMeta, MintInputError> {
        let input = input.ensure_v0_ref()?;

        let pk = self
            .cfg
            .consensus
            .tbs_agg_pks
            .get(&input.note.amount)
            .ok_or(MintInputError::InvalidAmountTier)?;

        if !input.note.verify(*pk) {
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
            .remove_entry(&IssuanceCounterKey(input.note.amount))
            .await
            .expect("Failed to retrieve issuance counter")
            .checked_sub(1)
            .expect("Failed to decrement issuance counter");

        dbtx.insert_new_entry(&IssuanceCounterKey(input.note.amount), &new_count)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.note.amount,
                fee: self.cfg.consensus.fee_consensus.fee(input.note.amount),
            },
            pub_key: input.note.nonce,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a MintOutput,
        _outpoint: OutPoint,
    ) -> Result<TransactionItemAmount, MintOutputError> {
        let output = output.ensure_v0_ref()?;

        let signature = self
            .cfg
            .private
            .tbs_sks
            .get(&output.amount)
            .map(|key| sign_blinded_msg(output.nonce, *key))
            .ok_or(MintOutputError::InvalidAmountTier)?;

        dbtx.insert_new_entry(&BlindedSignatureShareKey(output.nonce), &signature)
            .await;

        let new_count = dbtx
            .remove_entry(&IssuanceCounterKey(output.amount))
            .await
            .unwrap_or(0)
            .checked_add(1)
            .expect("Failed to increment issuance counter");

        dbtx.insert_new_entry(&IssuanceCounterKey(output.amount), &new_count)
            .await;

        Ok(TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.consensus.fee_consensus.fee(output.amount),
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
                -((k.0.msats * v) as i64)
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            SIGNATURE_SHARES_ENDPOINT,
            ApiVersion::new(0, 1),
            async |_module: &Mint, context, nonces: Vec<tbs::BlindedMessage>| -> Vec<BlindedSignatureShare> {
                let mut shares = Vec::new();

                for nonce in nonces {
                    let share = context.dbtx().get_value(&BlindedSignatureShareKey(nonce))
                        .await
                        .ok_or(ApiError::bad_request("No blinded signature share found".to_string()))?;

                    shares.push(share);
                }

                Ok(shares)
            }
        }]
    }
}

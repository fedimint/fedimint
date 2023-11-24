use std::collections::{BTreeMap, HashMap};
use std::iter::FromIterator;

use anyhow::bail;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::endpoint_constants::{BACKUP_ENDPOINT, RECOVER_ENDPOINT};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions,
    TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{
    apply, async_trait_maybe_send, push_db_key_items, push_db_pair_items, Amount, NumPeers,
    OutPoint, PeerId, ServerModule, Tiered, TieredMultiZip,
};
pub use fedimint_mint_common as common;
use fedimint_mint_common::config::{
    FeeConsensus, MintClientConfig, MintConfig, MintConfigConsensus, MintConfigLocal,
    MintConfigPrivate, MintGenParams,
};
use fedimint_mint_common::db::{
    DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix, MintAuditItemKey,
    MintAuditItemKeyPrefix, MintOutputOutcomeKey, MintOutputOutcomePrefix, NonceKey,
    NonceKeyPrefix,
};
pub use fedimint_mint_common::{BackupRequest, SignedBackupRequest};
use fedimint_mint_common::{
    MintCommonInit, MintConsensusItem, MintInput, MintInputError, MintModuleTypes, MintOutput,
    MintOutputError, MintOutputOutcome, DEFAULT_MAX_NOTES_PER_DENOMINATION,
};
use fedimint_server::config::distributedgen::{scalar, PeerHandleOps};
use futures::StreamExt;
use itertools::Itertools;
use secp256k1_zkp::SECP256K1;
use strum::IntoEnumIterator;
use tbs::{
    dealer_keygen, sign_blinded_msg, Aggregatable, AggregatePublicKey, PublicKeyShare,
    SecretKeyShare,
};
use threshold_crypto::group::Curve;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct MintInit;

#[apply(async_trait_maybe_send!)]
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
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw((u32::MAX, 0), (0, 0), &[(0, 0)])
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
                                    .gen_denominations()
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

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b MintInput,
    ) -> Result<InputMeta, MintInputError> {
        let input = input.ensure_v0_ref()?;

        let amount_key = self
            .pub_key
            .get(&input.amount)
            .ok_or(MintInputError::InvalidAmountTier(input.amount))?;

        if !input.note.verify(*amount_key) {
            return Err(MintInputError::InvalidSignature);
        }

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

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.fee_consensus.note_spend_abs,
            },
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

        Ok(TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.consensus.fee_consensus.note_issuance_abs,
        })
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

        audit
            .add_items(
                dbtx,
                module_instance_id,
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
                BACKUP_ENDPOINT,
                async |module: &Mint, context, request: SignedBackupRequest| -> () {
                    module
                        .handle_backup_request(&mut context.dbtx().into_nc(), request).await?;
                    Ok(())
                }
            },
            api_endpoint! {
                RECOVER_ENDPOINT,
                async |module: &Mint, context, id: secp256k1_zkp::PublicKey| -> Option<ECashUserBackupSnapshot> {
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
        dbtx: &mut DatabaseTransaction<'_>,
        id: secp256k1_zkp::PublicKey,
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
        Mint, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate, MintGenParams,
        MintInit,
    };

    const MINTS: usize = 5;

    fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
        let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
        let mint_cfg = MintInit.trusted_dealer_gen(
            &peers,
            &ConfigGenModuleParams::from_typed(MintGenParams {
                local: Default::default(),
                consensus: MintGenParamsConsensus::new(2),
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
        let nonce = Nonce(note_key.public_key());
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
                    .expect("Mint cannot issue a note of this denomination");
                tbs::sign_blinded_msg(blind_msg, sks)
            })
            .enumerate()
            .collect::<Vec<_>>();

        let blind_signature = tbs::combine_valid_shares(
            bsig_shares,
            server_cfgs.len() - ((server_cfgs.len() - 1) / 3),
        );
        let signature = tbs::unblind_signature(blinding_key, blind_signature);

        (note_key, Note { nonce, signature })
    }

    #[test_log::test(tokio::test)]
    async fn test_detect_double_spends() {
        let (mint_server_cfg, _) = build_configs();
        // TODO - Extract this from the config so we don't assume we're using base-2
        // denominations
        let even_denomination_amount = Amount::from_msats(1024);

        let mint = Mint::new(mint_server_cfg[0].to_typed().unwrap());
        let (_, note) = issue_note(&mint_server_cfg, even_denomination_amount);

        // Normal spend works
        let db = Database::new(MemDatabase::new(), Default::default());
        let input = MintInput::new_v0(even_denomination_amount, note);

        // Double spend in same epoch is detected
        let mut dbtx = db.begin_transaction().await;
        mint.process_input(&mut dbtx.to_ref_with_prefix_module_id(42).into_nc(), &input)
            .await
            .expect("Spend of valid e-cash works");
        assert_matches!(
            mint.process_input(&mut dbtx.to_ref_with_prefix_module_id(42).into_nc(), &input,)
                .await,
            Err(_)
        );
    }
}

#[cfg(test)]
mod fedimint_migration_tests {
    use anyhow::{ensure, Context};
    use bitcoin_hashes::Hash;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
    use fedimint_core::db::{
        apply_migrations, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::{CommonModuleInit, DynServerModuleInit};
    use fedimint_core::time::now;
    use fedimint_core::{Amount, OutPoint, ServerModule, TransactionId};
    use fedimint_mint_common::db::{
        DbKeyPrefix, ECashUserBackupSnapshot, EcashBackupKey, EcashBackupKeyPrefix,
        MintAuditItemKey, MintAuditItemKeyPrefix, MintOutputOutcomeKey, MintOutputOutcomePrefix,
        NonceKey, NonceKeyPrefix,
    };
    use fedimint_mint_common::{MintCommonInit, MintOutputOutcome, Nonce};
    use fedimint_testing::db::{
        prepare_db_migration_snapshot, validate_migrations, BYTE_32, BYTE_8,
    };
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use strum::IntoEnumIterator;
    use tbs::{
        blind_message, sign_blinded_msg, BlindingKey, FromRandom, Message, Scalar, SecretKeyShare,
    };

    use crate::{Mint, MintInit};

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let nonce_key = NonceKey(Nonce(pk));
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
        dbtx.insert_new_entry(
            &MintOutputOutcomeKey(out_point),
            &MintOutputOutcome::new_v0(blind_signature_share),
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

        let backup_key = EcashBackupKey(pk);
        let ecash_backup = ECashUserBackupSnapshot {
            timestamp: now(),
            data: BYTE_32.to_vec(),
        };
        dbtx.insert_new_entry(&backup_key, &ecash_backup).await;
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
                MintCommonInit::KIND,
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
                let module = DynServerModuleInit::from(MintInit);
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
                        DbKeyPrefix::OutputOutcome => {
                            let outcomes = dbtx
                                .find_by_prefix(&MintOutputOutcomePrefix)
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
                MintCommonInit::KIND,
                <Mint as ServerModule>::decoder(),
            )]),
        )
        .await
        .context("Migration validation")
        .unwrap();
    }
}

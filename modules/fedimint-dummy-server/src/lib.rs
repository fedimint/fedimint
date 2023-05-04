use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::string::ToString;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ClientModuleConfig, ConfigGenModuleParams, DkgResult, ServerModuleConfig,
    ServerModuleConsensusConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::epoch::{SerdeSignature, SerdeSignatureShare};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ConsensusProposal, CoreConsensusVersion, ExtendsCommonModuleGen,
    InputMeta, IntoModuleError, ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleGen,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{push_db_pair_items, Amount, NumPeers, OutPoint, PeerId, ServerModule};
use fedimint_dummy_common::config::{
    DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigPrivate,
};
use fedimint_dummy_common::{
    fed_public_key, DummyCommonGen, DummyConfigGenParams, DummyConsensusItem, DummyError,
    DummyInput, DummyModuleTypes, DummyOutput, DummyOutputOutcome, CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::{FutureExt, StreamExt};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeySet, SignatureShare};
use tokio::sync::Notify;

use crate::db::{
    migrate_to_v1, DbKeyPrefix, DummyFundsKeyV1, DummyFundsKeyV1Prefix, DummyOutcomeKeyV1,
    DummyOutcomeKeyV1Prefix, DummySignKeyV1, DummySignV1Prefix,
};

mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct DummyGen;

// TODO: Boilerplate-code
impl ExtendsCommonModuleGen for DummyGen {
    type Common = DummyCommonGen;
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleGen for DummyGen {
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    /// Initialize the module
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Dummy::new(cfg.to_typed()?).into())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> MigrationMap {
        let mut migrations = MigrationMap::new();
        migrations.insert(DatabaseVersion(0), move |dbtx| migrate_to_v1(dbtx).boxed());
        migrations
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        // Coerce config gen params into type
        let params = params.to_typed::<DummyConfigGenParams>().unwrap();
        // Create trusted set of threshold keys
        let sks = SecretKeySet::random(peers.degree(), &mut OsRng);
        let pks: PublicKeySet = sks.public_keys();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let private_key_share = SerdeSecret(sks.secret_key_share(peer.to_usize()));
                let config = DummyConfig {
                    private: DummyConfigPrivate { private_key_share },
                    consensus: DummyConfigConsensus {
                        public_key_set: pks.clone(),
                        tx_fee: params.tx_fee,
                    },
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        // Coerce config gen params into type
        let params = params.to_typed::<DummyConfigGenParams>().unwrap();
        // Runs distributed key generation
        // Could create multiple keys, here we use '()' to create one
        let g1 = peers.run_dkg_g1(()).await?;
        let keys = g1[&()].threshold_crypto();

        Ok(DummyConfig {
            private: DummyConfigPrivate {
                private_key_share: keys.secret_key_share,
            },
            consensus: DummyConfigConsensus {
                public_key_set: keys.public_key_set,
                tx_fee: params.tx_fee,
            },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        let config = DummyConfigConsensus::from_erased(config)?;
        Ok(ClientModuleConfig::from_typed(
            config.kind(),
            config.version(),
            &(DummyClientConfig {
                tx_fee: config.tx_fee,
                fed_public_key: config.public_key_set.public_key(),
            }),
        )
        .expect("Serialization can't fail"))
    }

    /// Validates the private/public key of configs
    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<DummyConfig>()?;
        let our_id = identity.to_usize();
        let our_share = config.consensus.public_key_set.public_key_share(our_id);

        // Check our private key matches our public key share
        if config.private.private_key_share.public_key_share() != our_share {
            bail!("Private key doesn't match public key share");
        }
        Ok(())
    }

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        // TODO: Boilerplate-code
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Funds => {
                    push_db_pair_items!(
                        dbtx,
                        DummyFundsKeyV1Prefix,
                        DummyFundsKeyV1,
                        Amount,
                        items,
                        "Dummy Funds"
                    );
                }
                DbKeyPrefix::Outcome => {
                    push_db_pair_items!(
                        dbtx,
                        DummyOutcomeKeyV1Prefix,
                        DummyOutcomeKeyV1,
                        DummyOutputOutcome,
                        items,
                        "Dummy Outputs"
                    );
                }
                DbKeyPrefix::Sign => {
                    push_db_pair_items!(
                        dbtx,
                        DummySignV1Prefix,
                        DummySignKeyV1,
                        Option<SerdeSignature>,
                        items,
                        "Dummy Sign"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
    /// Notifies us to propose an epoch
    pub sign_notify: Notify,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Dummy {
    /// Define the consensus types
    type Common = DummyModuleTypes;
    type Gen = DummyGen;
    type VerificationCache = DummyVerificationCache;

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(0, 0, &[(0, 0)])
    }

    async fn await_consensus_proposal(&self, dbtx: &mut ModuleDatabaseTransaction<'_>) {
        // Wait until we have a proposal
        if !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            self.sign_notify.notified().await;
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<DummyConsensusItem> {
        // Sign and send the print requests to consensus
        let items =
            dbtx.find_by_prefix(&DummySignV1Prefix)
                .await
                .map(|(DummySignKeyV1(message), _)| {
                    let sig = self.cfg.private.private_key_share.sign(&message);
                    DummyConsensusItem::Sign(message, SerdeSignatureShare(sig))
                });
        ConsensusProposal::new_auto_trigger(items.collect().await)
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, DummyConsensusItem)>,
        _consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId> {
        // Collect all signatures consensus items by message
        let mut sigs = HashMap::<String, Vec<(usize, &SignatureShare)>>::new();
        for (peer, DummyConsensusItem::Sign(request, share)) in &consensus_items {
            let entry = sigs.entry(request.clone()).or_default();
            entry.push((peer.to_usize(), &share.0));
        }

        let pks = self.cfg.consensus.public_key_set.clone();
        for (message, shares) in sigs {
            let key = DummySignKeyV1(message.to_string());

            // If a threshold of us signed, we can combine signatures
            // TODO: We could make combining + verifying peer sigs easier
            match pks.combine_signatures(shares) {
                Ok(sig) if pks.public_key().verify(&sig, &message) => {
                    dbtx.insert_entry(&key, &Some(SerdeSignature(sig))).await;
                }
                _ => {
                    dbtx.insert_entry(&key, &None).await;
                }
            }
        }
        vec![]
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a DummyInput> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        input: &'a DummyInput,
    ) -> Result<InputMeta, ModuleError> {
        let current_funds = dbtx.get_value(&DummyFundsKeyV1(input.account)).await;
        let enough_funds = input.amount <= current_funds.unwrap_or(Amount::ZERO);

        // verify user has enough funds or is using the fed account
        if enough_funds || fed_public_key() == input.account {
            return Ok(InputMeta {
                amount: TransactionItemAmount {
                    amount: input.amount,
                    fee: self.cfg.consensus.tx_fee,
                },
                // IMPORTANT: include the pubkey to validate the user signed this tx
                puk_keys: vec![input.account],
            });
        }

        Err(DummyError::NotEnoughFunds).into_module_error_other()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b DummyInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        // TODO: Boiler-plate code
        let meta = self
            .validate_input(interconnect, dbtx, cache, input)
            .await?;

        let current_funds = dbtx.get_value(&DummyFundsKeyV1(input.account)).await;
        // Subtract funds from normal user, or print funds for the fed
        let updated_funds = if fed_public_key() == input.account {
            current_funds.unwrap_or(Amount::ZERO) + input.amount
        } else {
            current_funds.unwrap_or(Amount::ZERO) - input.amount
        };
        dbtx.insert_entry(&DummyFundsKeyV1(input.account), &updated_funds)
            .await;

        Ok(meta)
    }

    async fn validate_output(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        output: &DummyOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        Ok(TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.consensus.tx_fee,
        })
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        output: &'a DummyOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        // TODO: Boiler-plate code
        let meta = self.validate_output(dbtx, output).await?;

        // Add output funds to the user's account
        let current_funds = dbtx.get_value(&DummyFundsKeyV1(output.account)).await;
        let updated_funds = current_funds.unwrap_or(Amount::ZERO) + output.amount;
        dbtx.insert_entry(&DummyFundsKeyV1(output.account), &updated_funds)
            .await;

        // Update the output outcome the user can query
        let outcome = DummyOutputOutcome(updated_funds, output.account);
        dbtx.insert_entry(&DummyOutcomeKeyV1(out_point), &outcome)
            .await;

        Ok(meta)
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &BTreeSet<PeerId>,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        // check whether or not the output has been processed
        dbtx.get_value(&DummyOutcomeKeyV1(out_point)).await
    }

    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(dbtx, &DummyFundsKeyV1Prefix, |k, v| match k {
                // the fed's test account is considered an asset (positive)
                // should be the bitcoin we own in a real module
                DummyFundsKeyV1(key) if key == fed_public_key() => v.msats as i64,
                // a user's funds are a federation's liability (negative)
                DummyFundsKeyV1(_) => -(v.msats as i64),
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                // API allows users ask the fed to threshold-sign a message
                "sign_message",
                async |module: &Dummy, context, message: String| -> () {
                    // TODO: Should not write to DB in module APIs
                    let mut dbtx = context.dbtx();
                    dbtx.insert_entry(&DummySignKeyV1(message), &None).await;
                    module.sign_notify.notify_one();
                    Ok(())
                }
            },
            api_endpoint! {
                // API waits for the signature to exist
                "wait_signed",
                async |_module: &Dummy, context, message: String| -> SerdeSignature {
                    let future = context.wait_value_matches(DummySignKeyV1(message), |sig| sig.is_some());
                    let sig = future.await;
                    Ok(sig.expect("checked is some"))
                }
            },
        ]
    }
}

/// An in-memory cache we could use for faster validation
#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

impl fedimint_core::server::VerificationCache for DummyVerificationCache {}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy {
            cfg,
            sign_notify: Notify::new(),
        }
    }
}

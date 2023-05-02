use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::string::ToString;

use async_trait::async_trait;
use fedimint_core::config::{
    ClientModuleConfig, ConfigGenModuleParams, DkgResult, ServerModuleConfig,
    ServerModuleConsensusConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::encoding::Encodable;
use fedimint_core::epoch::SerdeSignatureShare;
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
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::{
    DummyCommonGen, DummyConfigGenParams, DummyConsensusItem, DummyError, DummyInput,
    DummyModuleTypes, DummyOutput, DummyOutputOutcome, DummyPrintMoneyRequest, CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::{FutureExt, StreamExt};
use rand::rngs::OsRng;
use secp256k1::XOnlyPublicKey;
use strum::IntoEnumIterator;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeySet, SignatureShare};
use tokio::sync::Notify;

use crate::db::{
    migrate_to_v1, DbKeyPrefix, DummyFundsKeyV1, DummyFundsKeyV1Prefix, DummyOutcomeKeyV1,
    DummyOutcomeKeyV1Prefix, DummyPrintKeyV1, DummyPrintKeyV1Prefix,
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

    // TODO: Boilerplate-code
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        Ok(DummyConfigConsensus::from_erased(config)?.to_client_config())
    }

    // TODO: Boilerplate-code
    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<DummyConfig>()?.validate_config(identity)
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
                DbKeyPrefix::Print => {
                    push_db_pair_items!(
                        dbtx,
                        DummyPrintKeyV1Prefix,
                        DummyPrintKeyV1,
                        (),
                        items,
                        "Dummy Print"
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
    pub print_notify: Notify,
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
            self.print_notify.notified().await;
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> ConsensusProposal<DummyConsensusItem> {
        // Sign and send the print requests to consensus
        let items = dbtx.find_by_prefix(&DummyPrintKeyV1Prefix).await.map(
            |(DummyPrintKeyV1(request), _)| {
                let encoded_request = request.consensus_encode_to_vec().unwrap();
                let sig = self.cfg.private.private_key_share.sign(encoded_request);
                DummyConsensusItem::Print(request, SerdeSignatureShare(sig))
            },
        );
        ConsensusProposal::new_auto_trigger(items.collect().await)
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, DummyConsensusItem)>,
        _consensus_peers: &BTreeSet<PeerId>,
    ) -> Vec<PeerId> {
        // TODO: We could make combining peer sigs easier since it's often used

        // Collect all signatures by request
        let mut requests = HashMap::<DummyPrintMoneyRequest, Vec<(usize, &SignatureShare)>>::new();
        for (peer, DummyConsensusItem::Print(request, share)) in &consensus_items {
            let entry = requests.entry(request.clone()).or_default();
            entry.push((peer.to_usize(), &share.0));
        }

        let pks = self.cfg.consensus.public_key_set.clone();
        for (request, shares) in requests {
            // If a threshold of us signed, we can combine signatures
            let encoded_request = request.consensus_encode_to_vec().unwrap();
            if let Ok(sig) = pks.combine_signatures(shares) {
                if pks.public_key().verify(&sig, encoded_request) {
                    // If request is properly signed remove the consensus item
                    dbtx.remove_entry(&DummyPrintKeyV1(request.clone())).await;
                    // Add money to the user's account
                    let amount = get_funds(&request.account, dbtx).await + request.amount;
                    dbtx.insert_entry(&DummyFundsKeyV1(request.account), &amount)
                        .await;
                    // Print fake assets for the fed's balance sheet audit
                    dbtx.insert_entry(&DummyFundsKeyV1(fed_account()), &amount)
                        .await;
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
        // verify user has enough funds
        if input.amount > get_funds(&input.account, dbtx).await {
            return Err(DummyError::NotEnoughFunds).into_module_error_other();
        }

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.tx_fee,
            },
            // IMPORTANT: include the pubkey to validate the user signed this tx
            puk_keys: vec![input.account],
        })
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

        // subtract funds from the user's account
        let updated = get_funds(&input.account, dbtx).await - input.amount;
        dbtx.insert_entry(&DummyFundsKeyV1(input.account), &updated)
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

        let updated = get_funds(&output.account, dbtx).await + output.amount;
        // insert the output key for users to fetch the tx outcome
        let outcome = DummyOutputOutcome(updated, output.account);
        dbtx.insert_entry(&DummyOutcomeKeyV1(out_point), &outcome)
            .await;
        // add funds to the user's account
        dbtx.insert_entry(&DummyFundsKeyV1(output.account), &updated)
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
                // special account for creating assets (positive)
                DummyFundsKeyV1(key) if key == fed_account() => v.msats as i64,
                // a user's funds are a federation's liability (negative)
                DummyFundsKeyV1(_) => -(v.msats as i64),
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                // API allows users ask the fed to print money
                "print_money",
                async |module: &Dummy, context, request: DummyPrintMoneyRequest| -> () {
                    // TODO: A way to send messages to consensus without the DB
                    let mut dbtx = context.dbtx();
                    dbtx.insert_entry(&DummyPrintKeyV1(request), &()).await;
                    module.print_notify.notify_one();
                    Ok(())
                }
            },
            api_endpoint! {
                // API allows users to wait for an account to exist
                "wait_for_money",
                async |_module: &Dummy, context, account: XOnlyPublicKey| -> Amount {
                    // TODO: Wait for a change or non-existence of a key
                    let future = context.wait_key_exists(DummyFundsKeyV1(account));
                    let funds = future.await;
                    Ok(funds)
                }
            },
        ]
    }
}

fn fed_account() -> XOnlyPublicKey {
    let account_bytes = "Money printer go brrr...........".as_bytes();
    XOnlyPublicKey::from_slice(account_bytes).expect("32 bytes")
}

/// Helper to get the funds for an account
async fn get_funds<'a>(key: &XOnlyPublicKey, dbtx: &mut ModuleDatabaseTransaction<'a>) -> Amount {
    let funds = dbtx.get_value(&DummyFundsKeyV1(*key)).await;
    funds.unwrap_or(Amount::ZERO)
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
            print_notify: Notify::new(),
        }
    }
}

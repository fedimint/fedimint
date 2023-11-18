use std::collections::BTreeMap;
use std::string::ToString;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped, MigrationMap,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit, PeerHandle,
    ServerModuleInit, ServerModuleInitArgs, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{push_db_pair_items, Amount, OutPoint, PeerId, ServerModule};
use fedimint_dummy_common::config::{
    DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigLocal, DummyConfigPrivate,
    DummyGenParams,
};
use fedimint_dummy_common::{
    broken_fed_public_key, fed_public_key, DummyCommonInit, DummyConsensusItem, DummyInput,
    DummyInputError, DummyModuleTypes, DummyOutput, DummyOutputError, DummyOutputOutcome,
    CONSENSUS_VERSION,
};
use futures::{FutureExt, StreamExt};
use strum::IntoEnumIterator;

use crate::db::{
    migrate_to_v1, DbKeyPrefix, DummyFundsKeyV1, DummyFundsPrefixV1, DummyOutcomeKey,
    DummyOutcomePrefix,
};

mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct DummyInit;

// TODO: Boilerplate-code
#[async_trait]
impl ModuleInit for DummyInit {
    type Common = DummyCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
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
                        DummyFundsPrefixV1,
                        DummyFundsKeyV1,
                        Amount,
                        items,
                        "Dummy Funds"
                    );
                }
                DbKeyPrefix::Outcome => {
                    push_db_pair_items!(
                        dbtx,
                        DummyOutcomePrefix,
                        DummyOutcomeKey,
                        DummyOutputOutcome,
                        items,
                        "Dummy Outputs"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for DummyInit {
    type Params = DummyGenParams;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(u32::MAX, 0, &[(0, 0)])
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Dummy::new(args.cfg().to_typed()?).into())
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
        let params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = DummyConfig {
                    local: DummyConfigLocal {
                        example: params.local.0.clone(),
                    },
                    private: DummyConfigPrivate,
                    consensus: DummyConfigConsensus {
                        tx_fee: params.consensus.tx_fee,
                    },
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();

        Ok(DummyConfig {
            local: DummyConfigLocal {
                example: params.local.0.clone(),
            },
            private: DummyConfigPrivate,
            consensus: DummyConfigConsensus {
                tx_fee: params.consensus.tx_fee,
            },
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<DummyClientConfig> {
        let config = DummyConfigConsensus::from_erased(config)?;
        Ok(DummyClientConfig {
            tx_fee: config.tx_fee,
        })
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Dummy {
    /// Define the consensus types
    type Common = DummyModuleTypes;
    type Init = DummyInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_, '_>,
    ) -> Vec<DummyConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'_, 'b>,
        _consensus_item: DummyConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        bail!("The dummy module does not use consensus items");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_, 'c>,
        input: &'b DummyInput,
    ) -> Result<InputMeta, DummyInputError> {
        let current_funds = dbtx
            .get_value(&DummyFundsKeyV1(input.account))
            .await
            .unwrap_or(Amount::ZERO);

        // verify user has enough funds or is using the fed account
        if input.amount > current_funds
            && fed_public_key() != input.account
            && broken_fed_public_key() != input.account
        {
            return Err(DummyInputError::NotEnoughFunds);
        }

        // Subtract funds from normal user, or print funds for the fed
        let updated_funds = if fed_public_key() == input.account {
            current_funds + input.amount
        } else if broken_fed_public_key() == input.account {
            // The printer is broken
            current_funds
        } else {
            current_funds - input.amount
        };

        dbtx.insert_entry(&DummyFundsKeyV1(input.account), &updated_funds)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.tx_fee,
            },
            // IMPORTANT: include the pubkey to validate the user signed this tx
            pub_key: input.account,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_, 'b>,
        output: &'a DummyOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, DummyOutputError> {
        // Add output funds to the user's account
        let current_funds = dbtx.get_value(&DummyFundsKeyV1(output.account)).await;
        let updated_funds = current_funds.unwrap_or(Amount::ZERO) + output.amount;
        dbtx.insert_entry(&DummyFundsKeyV1(output.account), &updated_funds)
            .await;

        // Update the output outcome the user can query
        let outcome = DummyOutputOutcome(updated_funds, output.account);
        dbtx.insert_entry(&DummyOutcomeKey(out_point), &outcome)
            .await;

        Ok(TransactionItemAmount {
            amount: output.amount,
            fee: self.cfg.consensus.tx_fee,
        })
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        // check whether or not the output has been processed
        dbtx.get_value(&DummyOutcomeKey(out_point)).await
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_, '_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &DummyFundsPrefixV1,
                |k, v| match k {
                    // the fed's test account is considered an asset (positive)
                    // should be the bitcoin we own in a real module
                    DummyFundsKeyV1(key)
                        if key == fed_public_key() || key == broken_fed_public_key() =>
                    {
                        v.msats as i64
                    }
                    // a user's funds are a federation's liability (negative)
                    DummyFundsKeyV1(_) => -(v.msats as i64),
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy { cfg }
    }
}

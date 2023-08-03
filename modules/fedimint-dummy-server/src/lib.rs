use std::collections::BTreeMap;
use std::string::ToString;

use anyhow::bail;
use async_trait::async_trait;
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::epoch::{SerdeSignature, SerdeSignatureShare};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ConsensusProposal, CoreConsensusVersion, ExtendsCommonModuleGen,
    InputMeta, IntoModuleError, ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleGen,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{push_db_pair_items, Amount, NumPeers, OutPoint, PeerId, ServerModule};
use fedimint_dummy_common::config::{
    DummyClientConfig, DummyConfig, DummyConfigConsensus, DummyConfigLocal, DummyConfigPrivate,
    DummyGenParams,
};
use fedimint_dummy_common::{
    fed_public_key, DummyCommonGen, DummyConsensusItem, DummyError, DummyInput, DummyModuleTypes,
    DummyOutput, DummyOutputOutcome, CONSENSUS_VERSION,
};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::{FutureExt, StreamExt};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeySet};
use tokio::sync::Notify;

use crate::db::{
    migrate_to_v1, DbKeyPrefix, DummyFundsKeyV1, DummyFundsPrefixV1, DummyOutcomeKey,
    DummyOutcomePrefix, DummySignatureKey, DummySignaturePrefix, DummySignatureShareKey,
    DummySignatureSharePrefix, DummySignatureShareStringPrefix,
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
    type Params = DummyGenParams;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(0, 0, &[(0, 0)])
    }

    /// Initialize the module
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
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
        let params = self.parse_params(params).unwrap();
        // Create trusted set of threshold keys
        let sks = SecretKeySet::random(peers.degree(), &mut OsRng);
        let pks: PublicKeySet = sks.public_keys();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let private_key_share = SerdeSecret(sks.secret_key_share(peer.to_usize()));
                let config = DummyConfig {
                    local: DummyConfigLocal {
                        example: params.local.0.clone(),
                    },
                    private: DummyConfigPrivate { private_key_share },
                    consensus: DummyConfigConsensus {
                        public_key_set: pks.clone(),
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
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        // Runs distributed key generation
        // Could create multiple keys, here we use '()' to create one
        let g1 = peers.run_dkg_g1(()).await?;
        let keys = g1[&()].threshold_crypto();

        Ok(DummyConfig {
            local: DummyConfigLocal {
                example: params.local.0.clone(),
            },
            private: DummyConfigPrivate {
                private_key_share: keys.secret_key_share,
            },
            consensus: DummyConfigConsensus {
                public_key_set: keys.public_key_set,
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
            fed_public_key: config.public_key_set.public_key(),
        })
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
                DbKeyPrefix::SignatureShare => {
                    push_db_pair_items!(
                        dbtx,
                        DummySignatureSharePrefix,
                        DummySignatureShareKey,
                        SerdeSignatureShare,
                        items,
                        "Dummy Signature Shares"
                    );
                }
                DbKeyPrefix::Signature => {
                    push_db_pair_items!(
                        dbtx,
                        DummySignaturePrefix,
                        DummySignatureKey,
                        Option<SerdeSignature>,
                        items,
                        "Dummy Signatures"
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
        let sign_requests: Vec<_> = dbtx
            .find_by_prefix(&DummySignaturePrefix)
            .await
            .collect()
            .await;

        let consensus_items = sign_requests
            .into_iter()
            .filter(|(_, sig)| sig.is_none())
            .map(|(DummySignatureKey(message), _)| {
                let sig = self.cfg.private.private_key_share.sign(&message);
                DummyConsensusItem::Sign(message, SerdeSignatureShare(sig))
            });
        ConsensusProposal::new_auto_trigger(consensus_items.collect())
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_item: DummyConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let DummyConsensusItem::Sign(request, share) = consensus_item;

        if dbtx
            .get_value(&DummySignatureShareKey(request.clone(), peer_id))
            .await
            .is_some()
        {
            bail!("Already received a valid signature share")
        }

        if !self
            .cfg
            .consensus
            .public_key_set
            .public_key_share(peer_id.to_usize())
            .verify(&share.0, request.clone())
        {
            bail!("Signature share is invalid");
        }

        dbtx.insert_new_entry(&DummySignatureShareKey(request.clone(), peer_id), &share)
            .await;

        // Collect all valid signature shares previously received
        let signature_shares = dbtx
            .find_by_prefix(&DummySignatureShareStringPrefix(request.clone()))
            .await
            .collect::<Vec<_>>()
            .await;

        if signature_shares.len() <= self.cfg.consensus.public_key_set.threshold() {
            return Ok(());
        }

        let threshold_signature = self
            .cfg
            .consensus
            .public_key_set
            .combine_signatures(
                signature_shares
                    .iter()
                    .map(|(peer_id, share)| (peer_id.1.to_usize(), &share.0)),
            )
            .expect("We have verified all signature shares before");

        dbtx.remove_by_prefix(&DummySignatureShareStringPrefix(request.clone()))
            .await;

        dbtx.insert_entry(
            &DummySignatureKey(request.to_string()),
            &Some(SerdeSignature(threshold_signature)),
        )
        .await;

        Ok(())
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a DummyInput> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'c>,
        input: &'b DummyInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let current_funds = dbtx
            .get_value(&DummyFundsKeyV1(input.account))
            .await
            .unwrap_or(Amount::ZERO);

        // verify user has enough funds or is using the fed account
        if input.amount > current_funds && fed_public_key() != input.account {
            return Err(DummyError::NotEnoughFunds).into_module_error_other();
        }

        // Subtract funds from normal user, or print funds for the fed
        let updated_funds = if fed_public_key() == input.account {
            current_funds + input.amount
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
            pub_keys: vec![input.account],
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        output: &'a DummyOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
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
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<DummyOutputOutcome> {
        // check whether or not the output has been processed
        dbtx.get_value(&DummyOutcomeKey(out_point)).await
    }

    async fn audit(&self, dbtx: &mut ModuleDatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(dbtx, &DummyFundsPrefixV1, |k, v| match k {
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
                    dbtx.insert_entry(&DummySignatureKey(message), &None).await;
                    module.sign_notify.notify_one();
                    Ok(())
                }
            },
            api_endpoint! {
                // API waits for the signature to exist
                "wait_signed",
                async |_module: &Dummy, context, message: String| -> SerdeSignature {
                    let future = context.wait_value_matches(DummySignatureKey(message), |sig| sig.is_some());
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

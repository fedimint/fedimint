#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod db;

use std::collections::BTreeMap;
use std::future;

use async_trait::async_trait;
use db::{
    MetaConsensusKey, MetaDesiredKey, MetaDesiredValue, MetaSubmissionsByKeyPrefix,
    MetaSubmissionsKey,
};
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    CoreMigrationFn, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
    NonCommittable,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiAuth, ApiEndpoint, ApiError, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion,
    InputMeta, ModuleConsensusVersion, ModuleInit, PeerHandle, SupportedModuleApiVersions,
    TransactionItemAmount, api_endpoint,
};
use fedimint_core::{InPoint, NumPeers, OutPoint, PeerId, push_db_pair_items};
use fedimint_logging::LOG_MODULE_META;
use fedimint_meta_common::config::{
    MetaClientConfig, MetaConfig, MetaConfigConsensus, MetaConfigLocal, MetaConfigPrivate,
};
pub use fedimint_meta_common::config::{MetaGenParams, MetaGenParamsConsensus, MetaGenParamsLocal};
use fedimint_meta_common::endpoint::{
    GET_CONSENSUS_ENDPOINT, GET_CONSENSUS_REV_ENDPOINT, GET_SUBMISSIONS_ENDPOINT,
    GetConsensusRequest, GetSubmissionResponse, GetSubmissionsRequest, SUBMIT_ENDPOINT,
    SubmitRequest,
};
use fedimint_meta_common::{
    MODULE_CONSENSUS_VERSION, MetaCommonInit, MetaConsensusItem, MetaConsensusValue, MetaInput,
    MetaInputError, MetaKey, MetaModuleTypes, MetaOutput, MetaOutputError, MetaOutputOutcome,
    MetaValue,
};
use fedimint_server::core::{
    DynServerModule, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use rand::{Rng, thread_rng};
use strum::IntoEnumIterator;
use tracing::{debug, info, trace};

use crate::db::{
    DbKeyPrefix, MetaConsensusKeyPrefix, MetaDesiredKeyPrefix, MetaSubmissionValue,
    MetaSubmissionsKeyPrefix,
};

/// Generates the module
#[derive(Debug, Clone)]
pub struct MetaInit;

// TODO: Boilerplate-code
impl ModuleInit for MetaInit {
    type Common = MetaCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        // TODO: Boilerplate-code
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Desired => {
                    push_db_pair_items!(
                        dbtx,
                        MetaDesiredKeyPrefix,
                        MetaDesiredKey,
                        MetaDesiredValue,
                        items,
                        "Meta Desired"
                    );
                }
                DbKeyPrefix::Consensus => {
                    push_db_pair_items!(
                        dbtx,
                        MetaConsensusKeyPrefix,
                        MetaConsensusKey,
                        MetaConsensusValue,
                        items,
                        "Meta Consensus"
                    );
                }
                DbKeyPrefix::Submissions => {
                    push_db_pair_items!(
                        dbtx,
                        MetaSubmissionsKeyPrefix,
                        MetaSubmissionsKey,
                        MetaSubmissionValue,
                        items,
                        "Meta Submissions"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for MetaInit {
    type Module = Meta;
    type Params = MetaGenParams;

    /// Returns the version of this module
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

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Meta {
            cfg: args.cfg().to_typed()?,
            our_peer_id: args.our_peer_id(),
            num_peers: args.num_peers(),
        }
        .into())
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = MetaConfig {
                    local: MetaConfigLocal {},
                    private: MetaConfigPrivate,
                    consensus: MetaConfigConsensus {},
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
    ) -> anyhow::Result<ServerModuleConfig> {
        let _params = self.parse_params(params).unwrap();

        Ok(MetaConfig {
            local: MetaConfigLocal {},
            private: MetaConfigPrivate,
            consensus: MetaConfigConsensus {},
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<MetaClientConfig> {
        let _config = MetaConfigConsensus::from_erased(config)?;
        Ok(MetaClientConfig {})
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        BTreeMap::new()
    }
}

/// Meta module
#[derive(Debug)]
pub struct Meta {
    pub cfg: MetaConfig,
    pub our_peer_id: PeerId,
    pub num_peers: NumPeers,
}

impl Meta {
    async fn get_desired(dbtx: &mut DatabaseTransaction<'_>) -> Vec<(MetaKey, MetaDesiredValue)> {
        dbtx.find_by_prefix(&MetaDesiredKeyPrefix)
            .await
            .map(|(k, v)| (k.0, v))
            .collect()
            .await
    }

    async fn get_submission(
        dbtx: &mut DatabaseTransaction<'_>,
        key: MetaKey,
        peer_id: PeerId,
    ) -> Option<MetaSubmissionValue> {
        dbtx.get_value(&MetaSubmissionsKey { key, peer_id }).await
    }

    async fn get_consensus(dbtx: &mut DatabaseTransaction<'_>, key: MetaKey) -> Option<MetaValue> {
        dbtx.get_value(&MetaConsensusKey(key))
            .await
            .map(|consensus_value| consensus_value.value)
    }

    async fn change_consensus(
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        key: MetaKey,
        value: MetaValue,
        matching_submissions: Vec<PeerId>,
    ) {
        let value_len = value.as_slice().len();
        let revision = dbtx
            .get_value(&MetaConsensusKey(key))
            .await
            .map(|cv| cv.revision);
        let revision = revision.map(|r| r.wrapping_add(1)).unwrap_or_default();
        dbtx.insert_entry(
            &MetaConsensusKey(key),
            &MetaConsensusValue { revision, value },
        )
        .await;

        info!(target: LOG_MODULE_META, %key, rev = %revision, len = %value_len, "New consensus value");

        for peer_id in matching_submissions {
            dbtx.remove_entry(&MetaSubmissionsKey { key, peer_id })
                .await;
        }
    }
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Meta {
    /// Define the consensus types
    type Common = MetaModuleTypes;
    type Init = MetaInit;

    /// Check the difference between what's desired vs submitted and consensus.
    ///
    /// Returns:
    /// Items to submit as our proposal.
    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<MetaConsensusItem> {
        let desired: Vec<_> = Self::get_desired(dbtx).await;

        let mut to_submit = vec![];

        for (
            key,
            MetaDesiredValue {
                value: desired_value,
                salt,
            },
        ) in desired
        {
            let consensus_value = &Self::get_consensus(dbtx, key).await;
            let consensus_submission_value =
                Self::get_submission(dbtx, key, self.our_peer_id).await;
            if consensus_submission_value.as_ref()
                == Some(&MetaSubmissionValue {
                    value: desired_value.clone(),
                    salt,
                })
            {
                // our submission is already registered, nothing to do
            } else if consensus_value.as_ref() == Some(&desired_value) {
                if consensus_submission_value.is_none() {
                    // our desired value is equal to consensus and cleared our
                    // submission (as it is equal the
                    // consensus) so we don't need to propose it
                } else {
                    // we want to submit the same value as the current consensus, usually
                    // to clear the previous submission that did not became the consensus (we were
                    // outvoted)
                    to_submit.push(MetaConsensusItem {
                        key,
                        value: desired_value,
                        salt,
                    });
                }
            } else {
                to_submit.push(MetaConsensusItem {
                    key,
                    value: desired_value,
                    salt,
                });
            }
        }

        trace!(target: LOG_MODULE_META, ?to_submit, "Desired actions");
        to_submit
    }

    /// BUG: This implementation fails to return an `Err` on redundant consensus
    /// items. If you are using this code as a template,
    /// make sure to read the [`ServerModule::process_consensus_item`]
    /// documentation,
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        MetaConsensusItem { key, value, salt }: MetaConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        trace!(target: LOG_MODULE_META, %key, %value, %salt, "Processing consensus item proposal");

        let new_value = MetaSubmissionValue { salt, value };
        // first of all: any new submission overrides previous submission
        if let Some(prev_value) = Self::get_submission(dbtx, key, peer_id).await {
            if prev_value != new_value {
                dbtx.remove_entry(&MetaSubmissionsKey { key, peer_id })
                    .await;
            }
        }
        // then: if the submission is equal to the current consensus, it's ignored
        if Some(&new_value.value) == Self::get_consensus(dbtx, key).await.as_ref() {
            debug!(target: LOG_MODULE_META, %peer_id, %key, "Peer submitted a redundant value");
            return Ok(());
        }

        // otherwise, new submission is recorded
        dbtx.insert_entry(&MetaSubmissionsKey { key, peer_id }, &new_value)
            .await;

        // we check how many peers submitted the same value (including this peer)
        let matching_submissions: Vec<PeerId> = dbtx
            .find_by_prefix(&MetaSubmissionsByKeyPrefix(key))
            .await
            .filter(|(_submission_key, submission_value)| {
                future::ready(new_value.value == submission_value.value)
            })
            .map(|(submission_key, _)| submission_key.peer_id)
            .collect()
            .await;

        let threshold = self.num_peers.threshold();
        info!(target: LOG_MODULE_META,
             %peer_id,
             %key,
            value_len = %new_value.value.as_slice().len(),
             matching = %matching_submissions.len(),
            %threshold, "Peer submitted a value");

        // if threshold or more, change the consensus value
        if threshold <= matching_submissions.len() {
            Self::change_consensus(dbtx, key, new_value.value, matching_submissions).await;
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b MetaInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, MetaInputError> {
        Err(MetaInputError::NotSupported)
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a MetaOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, MetaOutputError> {
        Err(MetaOutputError::NotSupported)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<MetaOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                SUBMIT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Meta, context, request: SubmitRequest| -> () {

                    match context.request_auth() {
                        None => return Err(ApiError::bad_request("Missing password".to_string())),
                        Some(auth) => {
                            module.handle_submit_request(&mut context.dbtx(), &auth, &request).await?;
                        }
                    }

                    Ok(())
                }
            },
            api_endpoint! {
                GET_CONSENSUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Meta, context, request: GetConsensusRequest| -> Option<MetaConsensusValue> {
                    module.handle_get_consensus_request(&mut context.dbtx().into_nc(), &request).await
                }
            },
            api_endpoint! {
                GET_CONSENSUS_REV_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Meta, context, request: GetConsensusRequest| -> Option<u64> {
                    module.handle_get_consensus_revision_request(&mut context.dbtx().into_nc(), &request).await
                }
            },
            api_endpoint! {
                GET_SUBMISSIONS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Meta, context, request: GetSubmissionsRequest| -> GetSubmissionResponse {
                    match context.request_auth() {
                        None => return Err(ApiError::bad_request("Missing password".to_string())),
                        Some(auth) => {
                            module.handle_get_submissions_request(&mut context.dbtx().into_nc(),&auth, &request).await
                        }
                    }
                }
            },
        ]
    }
}

impl Meta {
    async fn handle_submit_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        _auth: &ApiAuth,
        req: &SubmitRequest,
    ) -> Result<(), ApiError> {
        let salt = thread_rng().r#gen();

        info!(target: LOG_MODULE_META,
             key = %req.key,
             peer_id = %self.our_peer_id,
             value_len = %req.value.as_slice().len(),
             "Our own guardian submitted a value");

        dbtx.insert_entry(
            &MetaDesiredKey(req.key),
            &MetaDesiredValue {
                value: req.value.clone(),
                salt,
            },
        )
        .await;

        Ok(())
    }

    async fn handle_get_consensus_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        req: &GetConsensusRequest,
    ) -> Result<Option<MetaConsensusValue>, ApiError> {
        Ok(dbtx.get_value(&MetaConsensusKey(req.0)).await)
    }

    async fn handle_get_consensus_revision_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        req: &GetConsensusRequest,
    ) -> Result<Option<u64>, ApiError> {
        Ok(dbtx
            .get_value(&MetaConsensusKey(req.0))
            .await
            .map(|cv| cv.revision))
    }

    async fn handle_get_submissions_request(
        &self,
        dbtx: &mut DatabaseTransaction<'_, NonCommittable>,
        _auth: &ApiAuth,
        req: &GetSubmissionsRequest,
    ) -> Result<BTreeMap<PeerId, MetaValue>, ApiError> {
        Ok(dbtx
            .find_by_prefix(&MetaSubmissionsByKeyPrefix(req.0))
            .await
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|(k, v)| (k.peer_id, v.value))
            .collect())
    }
}

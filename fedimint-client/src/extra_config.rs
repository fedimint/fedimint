//! Helper module for handling syncing of dynamically updated config between
//! client and server. See [`ExtraConfigService`] for more information.

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_core::config::ExtraConfig;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::runtime::sleep;
use fedimint_core::task::TaskGroup;
use fedimint_core::time::now;
use futures::future::join_all;
use tracing::warn;

use crate::db::{ExtraConfigKey, ExtraConfigValue};

#[derive(Debug, Default)]
pub struct ExtraConfigServiceBuilder {
    tracked_values: HashMap<ExtraConfigKey, (Duration, ValidationFn)>,
    db: Option<Database>,
    api: Option<DynGlobalApi>,
}

impl ExtraConfigServiceBuilder {
    /// Registers an extra config field not belonging to any module to be
    /// tracked by the service
    pub fn with_tracked_core_config(
        &mut self,
        tracked_values: impl IntoIterator<Item = TrackedExtraConfig>,
    ) {
        self.tracked_values
            .extend(tracked_values.into_iter().map(|tv| {
                (
                    ExtraConfigKey {
                        module_instance_id: None,
                        tracked_value: tv.fetch_method.to_owned(),
                    },
                    (tv.update_interval, tv.validation_fn),
                )
            }));
    }

    /// Registers an extra config field belonging to a module to be tracked by
    /// the service
    pub fn with_tracked_module_config(
        &mut self,
        module_instance_id: ModuleInstanceId,
        tracked_values: impl IntoIterator<Item = TrackedExtraConfig>,
    ) {
        self.tracked_values
            .extend(tracked_values.into_iter().map(|tv| {
                (
                    ExtraConfigKey {
                        module_instance_id: Some(module_instance_id),
                        tracked_value: tv.fetch_method.to_owned(),
                    },
                    (tv.update_interval, tv.validation_fn),
                )
            }));
    }

    /// Sets the database to use for storing the fetched values, mandatory.
    pub fn with_db(&mut self, db: Database) {
        self.db = Some(db);
    }

    /// Sets the API to use for fetching the values, mandatory.
    pub fn with_api(&mut self, api: DynGlobalApi) {
        self.api = Some(api);
    }

    /// Starts the service with the provided configuration and spawns a
    /// background task continuously updating the registered config fields. The
    /// task will shut down when the supplied task manager shuts down.
    pub fn start(self, task_group: &TaskGroup) -> ExtraConfigService {
        let db = self
            .db
            .expect("Database must be set before starting the service");
        let api = self
            .api
            .expect("API must be set before starting the service");

        let update_loops = self
            .tracked_values
            .iter()
            .map(|(extra_config_key, &(update_interval, validation_fn))| {
                let db = db.clone();
                let api = api.clone();
                let module_instance_id = extra_config_key.module_instance_id;
                let tracked_value = extra_config_key.tracked_value.clone();

                async move {
                    loop {
                        if let Err(e) = update_config_value(
                            &db,
                            &api,
                            module_instance_id,
                            &tracked_value,
                            validation_fn,
                        )
                        .await
                        {
                            warn!(%tracked_value, ?e, "Updating extra config field failed");
                        };
                        sleep(update_interval).await;
                    }
                }
            })
            .collect::<Vec<_>>();
        task_group.spawn_cancellable("dyn_cfg_sync", async move {
            join_all(update_loops).await;
        });

        ExtraConfigService {
            tracked_values: Arc::new(self.tracked_values.into_keys().collect()),
        }
    }
}

async fn update_config_value(
    db: &Database,
    api: &DynGlobalApi,
    module_instance_id: Option<ModuleInstanceId>,
    fetch_method: &str,
    validation_fn: ValidationFn,
) -> anyhow::Result<()> {
    let fetched_value = api
        .request_current_consensus::<serde_json::Value>(
            fetch_method.to_owned(),
            ApiRequestErased::default(),
        )
        .await?;

    validation_fn(fetched_value.clone())?;

    let db_key = ExtraConfigKey {
        module_instance_id,
        tracked_value: fetch_method.to_owned(),
    };
    let db_value = ExtraConfigValue {
        value: fetched_value,
        last_update: now(),
    };

    db.autocommit(
        |dbtx, _pd| {
            let db_key_inner = db_key.clone();
            let db_value_inner = db_value.clone();
            Box::pin(async move {
                dbtx.insert_entry(&db_key_inner, &db_value_inner).await;
                Result::<(), ()>::Ok(())
            })
        },
        None,
    )
    .await
    .expect("DB operation cannot fail");

    Ok(())
}

/// Service that keeps track of a fixed list of dynamic config fields. These are
/// regularly re-fetched from the server and saved in the DB. Use
/// `[DynConfigService::get_config_value]` to retrieve the latest value.
#[derive(Debug, Clone)]
pub struct ExtraConfigService {
    tracked_values: Arc<HashSet<ExtraConfigKey>>,
}

impl ExtraConfigService {
    // TODO: add example
    pub fn builder() -> ExtraConfigServiceBuilder {
        ExtraConfigServiceBuilder::default()
    }

    /// Returns the last fetched config value from the database. If the value
    /// wasn't fetched yet successfully returns `None`.
    pub async fn get_config_value<T: ExtraConfig>(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<T> {
        get_config_value(&self.tracked_values, dbtx, None).await
    }

    pub fn module_service(&self, module_instance_id: ModuleInstanceId) -> ModuleExtraConfigService {
        ModuleExtraConfigService {
            module_instance_id,
            tracked_values: self.tracked_values.clone(),
        }
    }
}

/// Reference to the [`ExtraConfigService`] that only allows accessing a
/// specific module's tracked extra config values.
#[derive(Debug, Clone)]
pub struct ModuleExtraConfigService {
    module_instance_id: ModuleInstanceId,
    tracked_values: Arc<HashSet<ExtraConfigKey>>,
}

impl ModuleExtraConfigService {
    /// Returns the last valid fetched config value from the database. If the
    /// value wan't fetched yet successfully returns `None`.
    pub async fn get_config_value<T: ExtraConfig>(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<T> {
        get_config_value(&self.tracked_values, dbtx, Some(self.module_instance_id)).await
    }
}

async fn get_config_value<T: ExtraConfig>(
    tracked_values: &HashSet<ExtraConfigKey>,
    dbtx: &mut DatabaseTransaction<'_>,
    module_instance_id: Option<ModuleInstanceId>,
) -> Option<T> {
    assert!(
        tracked_values.contains(&ExtraConfigKey {
            module_instance_id,
            tracked_value: T::FETCH_METHOD.to_owned(),
        }),
        "You need to register the dynamic config value first before reading it: {}",
        T::FETCH_METHOD
    );

    let db_key = ExtraConfigKey {
        module_instance_id,
        tracked_value: T::FETCH_METHOD.to_owned(),
    };

    let db_value = dbtx.get_value(&db_key).await.map(|db_val| db_val.value)?;

    serde_json::from_value(db_value).expect("Decodability was checked at fetch time")
}

type ValidationFn = fn(value: serde_json::Value) -> Result<(), anyhow::Error>;

#[derive(Debug, Clone)]
pub struct TrackedExtraConfig {
    fetch_method: &'static str,
    update_interval: Duration,
    validation_fn: ValidationFn,
}

pub trait ExtraConfigTacking {
    fn tracking_info() -> TrackedExtraConfig;
}

impl<T> ExtraConfigTacking for T
where
    T: ExtraConfig,
{
    /// Returns the tracking information for the extra config value that will be
    /// used to dynamically fetch it in the background.
    fn tracking_info() -> TrackedExtraConfig {
        TrackedExtraConfig {
            fetch_method: T::FETCH_METHOD,
            update_interval: T::UPDATE_INTERVAL,
            validation_fn: |value| {
                serde_json::from_value::<T>(value)?;
                Ok(())
            },
        }
    }
}

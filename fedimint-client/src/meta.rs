use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context as _};
use async_stream::stream;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::task::waiter::Waiter;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{retry, FibonacciBackoff};
use fedimint_core::{apply, async_trait_maybe_send};
use serde::de::DeserializeOwned;
use tokio::sync::Notify;
use tokio_stream::{Stream, StreamExt as _};
use tracing::{debug, instrument, warn};

use crate::db::{
    MetaFieldKey, MetaFieldPrefix, MetaFieldValue, MetaServiceInfo, MetaServiceInfoKey,
};
use crate::Client;

#[apply(async_trait_maybe_send!)]
pub trait MetaSource: MaybeSend + MaybeSync + 'static {
    /// Wait for next change in this source.
    async fn wait_for_update(&self);
    async fn fetch(
        &self,
        client: &Client,
        fetch_kind: FetchKind,
        last_revision: Option<u64>,
    ) -> anyhow::Result<MetaValues>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchKind {
    /// Meta source should return fast, retry less.
    /// This blocks getting any meta values.
    Initial,
    /// Meta source can retry infinitely.
    Background,
}

#[derive(Debug, Clone)]
pub struct MetaValues {
    values: BTreeMap<MetaFieldKey, MetaFieldValue>,
    revision: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MetaValue<T> {
    pub fetch_time: SystemTime,
    pub value: Option<T>,
}

/// Service for managing the caching of meta fields.
// a fancy DST to save one allocation.
pub struct MetaService<S: ?Sized = dyn MetaSource> {
    initial_fetch_waiter: Waiter,
    meta_update_notify: Notify,
    source: S,
}

impl<S: MetaSource + ?Sized> MetaService<S> {
    pub fn new(source: S) -> Arc<MetaService>
    where
        S: Sized,
    {
        // implicit cast `Arc<MetaService<S>>` to `Arc<MetaService<dyn MetaSource>>`
        Arc::new(MetaService {
            initial_fetch_waiter: Waiter::new(),
            meta_update_notify: Notify::new(),
            source,
        })
    }

    /// Get the value for the meta field.
    ///
    /// This may wait for significant time on first run.
    pub async fn get_field<V: DeserializeOwned + 'static>(
        &self,
        db: &Database,
        field: &str,
    ) -> Option<MetaValue<V>> {
        if let Some(value) = self.get_field_from_db(db, field).await {
            // might be from in old cache.
            // TODO: maybe old cache should have a ttl?
            Some(value)
        } else {
            // wait for initial value
            self.initial_fetch_waiter.wait().await;
            self.get_field_from_db(db, field).await
        }
    }

    async fn get_field_from_db<V: DeserializeOwned + 'static>(
        &self,
        db: &Database,
        field: &str,
    ) -> Option<MetaValue<V>> {
        let dbtx = &mut db.begin_transaction_nc().await;
        let info = dbtx.get_value(&MetaServiceInfoKey).await?;
        let value = dbtx
            .get_value(&MetaFieldKey(field.to_string()))
            .await
            .and_then(|value| parse_meta_value_static::<V>(&value.0).ok());
        Some(MetaValue {
            fetch_time: info.last_updated,
            value,
        })
    }

    async fn current_revision(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<u64> {
        dbtx.get_value(&MetaServiceInfoKey)
            .await
            .map(|x| x.revision)
    }

    /// Wait until Meta Service is initialized, after this `get_field` will not
    /// block.
    pub async fn wait_initialization(&self) {
        self.initial_fetch_waiter.wait().await
    }

    /// NOTE: this subscription never ends even after update task is shutdown.
    /// You should consume this stream in a spawn_cancellable.
    pub fn subscribe_to_updates(&self) -> impl Stream<Item = ()> + '_ {
        stream! {
            let mut notify = pin!(self.meta_update_notify.notified());
            loop {
                notify.as_mut().await;
                notify.set(self.meta_update_notify.notified());
                // enable waiting for next notification before yield so don't miss
                // any notifications.
                notify.as_mut().enable();
                yield ();
            }
        }
    }

    /// NOTE: this subscription never ends even after update task is shutdown.
    /// You should consume this stream in a spawn_cancellable.
    ///
    /// Stream will yield the first element immediately without blocking.
    /// The first element will be initial value of the field.
    ///
    /// This may yield an outdated initial value if you didn't call
    /// [`Self::wait_initialization`].
    pub fn subscribe_to_field<'a, V: DeserializeOwned + 'static>(
        &'a self,
        db: &'a Database,
        name: &'a str,
    ) -> impl Stream<Item = Option<MetaValue<V>>> + 'a {
        stream! {
            let mut update_stream = pin!(self.subscribe_to_updates());
            loop {
                let value = self.get_field_from_db(db, name).await;
                yield value;
                if update_stream.next().await.is_none() {
                    break;
                }
            }
        }
    }

    /// Update all source in background.
    ///
    /// Caller should run this method in a task.
    pub(crate) async fn update_continuously(&self, client: &Client) -> ! {
        let mut current_revision = self
            .current_revision(&mut client.db().begin_transaction_nc().await)
            .await;
        let meta_values = self
            .source
            .fetch(client, FetchKind::Initial, current_revision)
            .await;
        let failed_initial = meta_values.is_err();
        match meta_values {
            Ok(meta_values) => self.save_meta_values(client, &meta_values).await,
            Err(error) => warn!(%error, "failed to fetch source"),
        };
        self.initial_fetch_waiter.done();

        // don't wait if we failed first item
        if !failed_initial {
            self.source.wait_for_update().await;
        }

        // now keep updating slowly
        loop {
            if let Ok(meta_values) = self
                .source
                .fetch(client, FetchKind::Background, current_revision)
                .await
            {
                current_revision = Some(meta_values.revision);
                self.save_meta_values(client, &meta_values).await;
            }
            self.source.wait_for_update().await;
        }
    }

    async fn save_meta_values(&self, client: &Client, meta_values: &MetaValues) {
        let mut dbtx = client.db().begin_transaction().await;
        dbtx.remove_by_prefix(&MetaFieldPrefix).await;
        dbtx.insert_entry(
            &MetaServiceInfoKey,
            &MetaServiceInfo {
                last_updated: fedimint_core::time::now(),
                revision: meta_values.revision,
            },
        )
        .await;
        for (key, value) in &meta_values.values {
            dbtx.insert_entry(key, value).await;
        }
        dbtx.commit_tx().await;
        // notify everyone about changes
        self.meta_update_notify.notify_waiters();
    }
}

/// Legacy non-meta module config source uses client config meta and
/// meta_override_url meta field.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct LegacyMetaSource {
    reqwest: reqwest::Client,
}

#[apply(async_trait_maybe_send!)]
impl MetaSource for LegacyMetaSource {
    async fn wait_for_update(&self) {
        fedimint_core::runtime::sleep(Duration::from_secs(10 * 60)).await
    }

    async fn fetch(
        &self,
        client: &Client,
        fetch_kind: FetchKind,
        last_revision: Option<u64>,
    ) -> anyhow::Result<MetaValues> {
        let config_iter = client
            .config()
            .global
            .meta
            .iter()
            .map(|(key, value)| (MetaFieldKey(key.to_owned()), MetaFieldValue(value.clone())));
        let backoff = match fetch_kind {
            // need to be fast the first time.
            FetchKind::Initial => FibonacciBackoff::default()
                .with_min_delay(Duration::from_millis(300))
                .with_max_delay(Duration::from_secs(3))
                .with_max_times(10),
            FetchKind::Background => FibonacciBackoff::default()
                .with_min_delay(Duration::from_secs(10))
                .with_max_delay(Duration::from_secs(10 * 60))
                .with_max_times(usize::MAX),
        };
        let overrides = retry("fetch_meta_overrides", backoff, || {
            fetch_meta_overrides(&self.reqwest, client, "meta_override_url")
        })
        .await?;
        Ok(MetaValues {
            values: config_iter.chain(overrides).collect(),
            revision: last_revision.map_or(0, |r| r + 1),
        })
    }
}

pub async fn fetch_meta_overrides(
    reqwest: &reqwest::Client,
    client: &Client,
    field_name: &str,
) -> anyhow::Result<BTreeMap<MetaFieldKey, MetaFieldValue>> {
    let Some(url) = client.config().meta::<String>(field_name)? else {
        return Ok(BTreeMap::new());
    };
    let response = reqwest
        .get(&url)
        .send()
        .await
        .context("Meta override source could not be fetched")?;

    debug!("Meta override source returned status: {response:?}");

    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "Meta override request returned non-OK status code: {}",
            response.status()
        );
    }

    let mut federation_map = response
        .json::<BTreeMap<String, BTreeMap<String, serde_json::Value>>>()
        .await
        .context("Meta override could not be parsed as JSON")?;

    let federation_id = client.federation_id().to_string();
    let meta_fields = federation_map
        .remove(&federation_id)
        .with_context(|| anyhow::format_err!("No entry for federation {federation_id} in {url}"))?
        .into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(value_str) => {
                Some((MetaFieldKey(key), MetaFieldValue(value_str)))
            }
            _ => {
                warn!("Meta override map contained non-string key: {key}, ignoring");
                None
            }
        })
        .collect::<BTreeMap<_, _>>();

    Ok(meta_fields)
}

/// Tries to parse `str_value` as JSON. In the special case that `V` is `String`
/// we return the raw `str_value` if JSON parsing fails. This necessary since
/// the spec wasn't clear enough in the beginning.
#[instrument(err)] // log on every failure
pub fn parse_meta_value_static<V: DeserializeOwned + 'static>(
    str_value: &str,
) -> anyhow::Result<V> {
    let res = serde_json::from_str(str_value)
        .with_context(|| format!("Decoding meta field value '{str_value}' failed"));

    // In the past we encoded some string fields as "just a string" without quotes,
    // this code ensures that old meta values still parse since config is hard to
    // change
    if res.is_err() && std::any::TypeId::of::<V>() == std::any::TypeId::of::<String>() {
        let string_ret = Box::new(str_value.to_owned());
        let ret: Box<V> = unsafe {
            // We can transmute a String to V because we know that V==String
            std::mem::transmute(string_ret)
        };
        Ok(*ret)
    } else {
        res
    }
}

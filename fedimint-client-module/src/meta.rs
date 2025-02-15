use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context as _};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ClientConfig;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

#[apply(async_trait_maybe_send!)]
pub trait MetaSource: MaybeSend + MaybeSync + 'static {
    /// Wait for next change in this source.
    async fn wait_for_update(&self);
    async fn fetch(
        &self,
        client_config: &ClientConfig,
        api: &DynGlobalApi,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetaValues {
    pub values: BTreeMap<MetaFieldKey, MetaFieldValue>,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MetaValue<T> {
    pub fetch_time: SystemTime,
    pub value: Option<T>,
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
        fedimint_core::runtime::sleep(Duration::from_secs(10 * 60)).await;
    }

    async fn fetch(
        &self,
        client_config: &ClientConfig,
        _api: &DynGlobalApi,
        fetch_kind: FetchKind,
        last_revision: Option<u64>,
    ) -> anyhow::Result<MetaValues> {
        let config_iter = client_config
            .global
            .meta
            .iter()
            .map(|(key, value)| (MetaFieldKey(key.clone()), MetaFieldValue(value.clone())));
        let backoff = match fetch_kind {
            // need to be fast the first time.
            FetchKind::Initial => backoff_util::aggressive_backoff(),
            FetchKind::Background => backoff_util::background_backoff(),
        };
        let overrides = retry("fetch_meta_overrides", backoff, || {
            fetch_meta_overrides(&self.reqwest, client_config, "meta_override_url")
        })
        .await?;
        Ok(MetaValues {
            values: config_iter.chain(overrides).collect(),
            revision: last_revision.map_or(0, |r| r + 1),
        })
    }
}

#[derive(
    Encodable, Decodable, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize,
)]
pub struct MetaFieldKey(pub String);

#[derive(Encodable, Decodable, Debug, Clone, Serialize, Deserialize)]
pub struct MetaFieldValue(pub String);

pub async fn fetch_meta_overrides(
    reqwest: &reqwest::Client,
    client_config: &ClientConfig,
    field_name: &str,
) -> anyhow::Result<BTreeMap<MetaFieldKey, MetaFieldValue>> {
    let Some(url) = client_config.meta::<String>(field_name)? else {
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

    let federation_id = client_config.calculate_federation_id().to_string();
    let meta_fields = federation_map
        .remove(&federation_id)
        .with_context(|| anyhow::format_err!("No entry for federation {federation_id} in {url}"))?
        .into_iter()
        .filter_map(|(key, value)| {
            if let serde_json::Value::String(value_str) = value {
                Some((MetaFieldKey(key), MetaFieldValue(value_str)))
            } else {
                warn!(target: LOG_CLIENT, "Meta override map contained non-string key: {key}, ignoring");
                None
            }
        })
        .collect::<BTreeMap<_, _>>();

    Ok(meta_fields)
}

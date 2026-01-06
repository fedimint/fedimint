use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, bail};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::config::ClientConfig;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{FmtCompact as _, backoff_util, retry};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT;
use serde::{Deserialize, Serialize, de};
use tracing::debug;

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
        let config_iter = client_config.global.meta.iter().map(|(key, value)| {
            (
                MetaFieldKey(key.clone()),
                MetaFieldValue(serde_json::Value::String(value.clone())),
            )
        });
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

#[derive(Debug, Clone, Serialize)]
pub struct MetaFieldValue(pub serde_json::Value);

// In the past we did not support native serde_values as values,
// which required users to make the the complex meta values a json-escaped
// strings which is ... bleh.
//
// This custom Deserialize impl. "unpeals" the extra layer of json-escaping,
// if it passes, trying to support the old values like it. We probably
// should remove this workaround in some future.
impl<'de> Deserialize<'de> for MetaFieldValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        let final_value = if let serde_json::Value::String(s) = &value {
            // Try to parse the string as JSON
            match serde_json::from_str::<serde_json::Value>(s) {
                Ok(parsed) => parsed,
                Err(_) => value, // If parsing fails, use the original string value
            }
        } else {
            value
        };

        Ok(MetaFieldValue(final_value))
    }
}

impl Encodable for MetaFieldValue {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let s = serde_json::to_string(&self).expect("Can't fail");

        s.consensus_encode(writer)
    }
}

impl Decodable for MetaFieldValue {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let s = String::consensus_decode_partial(r, modules)?;

        Ok(Self(serde_json::from_str(&s).unwrap_or_else(|err| {
            debug!(
                target: LOG_CLIENT,
                err = %err.fmt_compact(),
                s = %s,
                "Failed to decode meta value in the db as json, falling back to string"
            );
            serde_json::Value::String(s)
        })))
    }
}

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
        .map(|(key, value)| (MetaFieldKey(key), MetaFieldValue(value)))
        .collect::<BTreeMap<_, _>>();

    Ok(meta_fields)
}

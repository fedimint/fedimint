use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use fedimint_core::bitcoin_rpc::DynBitcoindRpc;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Feerate};
use fedimint_logging::LOG_MODULE_WALLET;
use fedimint_wallet_common::CONFIRMATION_TARGET;
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Ctx, Native, RcIter};
use jaq_json::Val;
use tracing::{debug, trace};

/// A feerate that we don't expect to ever happen in practice, that we are
/// going to reject from a source to help catching mistakes and
/// misconfigurations.
const FEERATE_SOURCE_MAX_FEERATE_SATS_PER_VB: f64 = 10_000.0;

/// Like [`FEERATE_SOURCE_MAX_FEERATE_SATS_PER_VB`], but minimum one we accept
const FEERATE_SOURCE_MIN_FEERATE_SATS_PER_VB: f64 = 1.0;

#[apply(async_trait_maybe_send!)]
pub trait FeeRateSource: Send + Sync {
    fn name(&self) -> String;
    async fn fetch(&self) -> Result<Feerate>;
}

#[apply(async_trait_maybe_send!)]
impl FeeRateSource for DynBitcoindRpc {
    fn name(&self) -> String {
        self.get_bitcoin_rpc_config().kind
    }

    async fn fetch(&self) -> Result<Feerate> {
        self.get_fee_rate(CONFIRMATION_TARGET)
            .await?
            .ok_or_else(|| anyhow!("bitcoind did not return any feerate"))
    }
}

pub struct FetchJson {
    filter: jaq_core::Filter<Native<Val>>,
    source_url: SafeUrl,
}

impl FetchJson {
    pub fn from_str(source_str: &str) -> Result<Self> {
        let (source_url, code) = {
            let (url, code) = match source_str.split_once('#') {
                Some(val) => val,
                None => (source_str, "."),
            };

            (SafeUrl::parse(url)?, code)
        };

        debug!(target: LOG_MODULE_WALLET, url = %source_url, code = %code, "Setting fee rate json source");
        let program = File { code, path: () };

        let loader = Loader::new([]);
        let arena = Arena::default();
        let modules = loader.load(&arena, program).map_err(|errs| {
            anyhow!(
                "Error parsing jq filter for {source_url}: {}",
                errs.into_iter()
                    .map(|e| format!("{e:?}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        })?;

        let filter = jaq_core::Compiler::<_, Native<_>>::default()
            .compile(modules)
            .map_err(|errs| anyhow!("Failed to compile program: {:?}", errs))?;

        Ok(Self { filter, source_url })
    }

    fn apply_filter(&self, value: serde_json::Value) -> Result<Val> {
        let inputs = RcIter::new(core::iter::empty());

        let mut out = self.filter.run((Ctx::new([], &inputs), Val::from(value)));

        out.next()
            .ok_or_else(|| anyhow!("Missing value after applying filter"))?
            .map_err(|e| anyhow!("Jaq err: {e}"))
    }
}

#[apply(async_trait_maybe_send!)]
impl FeeRateSource for FetchJson {
    fn name(&self) -> String {
        self.source_url
            .host()
            .map_or_else(|| "host-not-available".to_string(), |h| h.to_string())
    }

    async fn fetch(&self) -> Result<Feerate> {
        let json_resp: serde_json::Value = reqwest::get(self.source_url.clone().to_unsafe())
            .await?
            .json()
            .await?;

        trace!(target: LOG_MODULE_WALLET, name = %self.name(), resp = ?json_resp, "Got json response");

        let val = self.apply_filter(json_resp)?;

        let rate = match val {
            Val::Float(rate) => rate,
            #[allow(clippy::cast_precision_loss)]
            Val::Int(rate) => rate as f64,
            Val::Num(rate) => FromStr::from_str(&rate)?,
            _ => {
                bail!("Value returned by feerate source has invalid type: {val:?}");
            }
        };
        debug!(target: LOG_MODULE_WALLET, name = %self.name(), rate_sats_vb = %rate, "Got fee rate");

        if rate < FEERATE_SOURCE_MIN_FEERATE_SATS_PER_VB {
            bail!("Fee rate returned by source not positive: {rate}")
        }

        if FEERATE_SOURCE_MAX_FEERATE_SATS_PER_VB <= rate {
            bail!("Fee rate returned by source too large: {rate}")
        }

        Ok(Feerate {
            // just checked that it's not negative
            #[allow(clippy::cast_sign_loss)]
            sats_per_kvb: (rate * 1000.0).floor() as u64,
        })
    }
}

#[cfg(test)]
mod test {
    use std::rc::Rc;

    use jaq_json::Val;

    use crate::feerate_source::FetchJson;

    fn val_str(s: &str) -> Val {
        Val::Str(Rc::new(s.to_owned()))
    }

    #[test]
    fn test_filter() {
        let source_id = FetchJson::from_str("https://example.com#.").expect("Failed to parse url");
        assert_eq!(
            source_id
                .apply_filter(serde_json::json!("foo"))
                .expect("Failed to apply filter"),
            val_str("foo")
        );

        let source_access_member =
            FetchJson::from_str("https://example.com#.[0].foo").expect("Failed to parse url");
        assert_eq!(
            source_access_member
                .apply_filter(serde_json::json!([{"foo": "bar"}, 1, 2, 3]))
                .expect("Failed to apply filter"),
            val_str("bar")
        );
    }
}

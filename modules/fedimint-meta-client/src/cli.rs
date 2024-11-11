use std::str::FromStr as _;
use std::{ffi, iter};

use anyhow::Context as _;
use clap::Parser;
use fedimint_meta_common::{MetaConsensusValue, MetaKey, MetaValue, DEFAULT_META_KEY};
use serde::Serialize;
use serde_json::json;

use super::MetaClientModule;
use crate::api::MetaFederationApi;

#[derive(Parser, Serialize)]
enum Opts {
    /// Get current consensus value
    Get {
        #[arg(long, default_value_t = DEFAULT_META_KEY)]
        key: MetaKey,
        #[arg(long)]
        hex: bool,
    },
    /// Get current consensus value revision
    GetRev {
        #[arg(long, default_value_t = DEFAULT_META_KEY)]
        key: MetaKey,
    },
    /// Get value change submissions
    GetSubmissions {
        #[arg(long, default_value_t = DEFAULT_META_KEY)]
        key: MetaKey,
        #[arg(long)]
        hex: bool,
    },
    /// Submit value change proposal
    Submit {
        #[arg(long, default_value_t = DEFAULT_META_KEY)]
        key: MetaKey,
        value: String,
        #[arg(long)]
        hex: bool,
    },
}

pub(crate) async fn handle_cli_command(
    meta: &MetaClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("meta")).chain(args.iter()));

    let res = match opts {
        Opts::Get { key, hex } => {
            if let Some(MetaConsensusValue { revision, value }) =
                meta.module_api.get_consensus(key).await?
            {
                let value = if hex {
                    serde_json::to_value(value).expect("can't fail")
                } else {
                    value
                        .to_json_lossy()
                        .context("deserializing consensus value as json")?
                };
                json!({
                    "revision": revision,
                    "value": value
                })
            } else {
                serde_json::Value::Null
            }
        }
        Opts::GetRev { key } => {
            if let Some(rev) = meta.module_api.get_consensus_rev(key).await? {
                json!({
                    "revision": rev,
                })
            } else {
                serde_json::Value::Null
            }
        }
        Opts::GetSubmissions { key, hex } => {
            let submissions = meta
                .module_api
                .get_submissions(key, meta.admin_auth()?)
                .await?;
            let submissions: serde_json::Map<String, serde_json::Value> = submissions
                .into_iter()
                .map(|(peer_id, value)| -> anyhow::Result<_> {
                    let value = if hex {
                        serde_json::Value::String(value.to_string())
                    } else {
                        serde_json::from_reader(value.as_slice())
                            .context("deserializing submission value")?
                    };

                    Ok((peer_id.to_string(), value))
                })
                .collect::<anyhow::Result<_, _>>()?;

            serde_json::Value::Object(submissions)
        }
        Opts::Submit { key, value, hex } => {
            let value: MetaValue = if hex {
                MetaValue::from_str(&value).context("value not a valid hex string")?
            } else {
                let _valid_json: serde_json::Value =
                    serde_json::from_str(&value).context("value not a valid json string")?;
                MetaValue::from(value.as_bytes())
            };

            meta.module_api
                .submit(key, value, meta.admin_auth()?)
                .await?;

            serde_json::Value::Bool(true)
        }
    };

    Ok(res)
}

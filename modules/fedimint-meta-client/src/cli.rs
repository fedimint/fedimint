use std::str::FromStr;
use std::{ffi, iter};

use clap::Parser;
use fedimint_api_client::api::FederationError;
use fedimint_meta_common::{DEFAULT_META_KEY, MetaConsensusValue, MetaKey, MetaValue};
use serde::Serialize;
use serde_json::json;

use super::MetaClientModule;
use crate::MetaAdminError;
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
) -> Result<serde_json::Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("meta")).chain(args.iter()));

    let res = match opts {
        Opts::Get { key, hex } => match meta.module_api.get_consensus(key).await? {
            Some(MetaConsensusValue { revision, value }) => {
                let value = if hex {
                    serde_json::to_value(value).expect("can't fail")
                } else {
                    value
                        .to_json_lossy()
                        .map_err(CliCommandError::ConsensusValueJson)?
                };
                json!({
                    "revision": revision,
                    "value": value
                })
            }
            _ => serde_json::Value::Null,
        },
        Opts::GetRev { key } => match meta.module_api.get_consensus_rev(key).await? {
            Some(rev) => {
                json!({
                    "revision": rev,
                })
            }
            _ => serde_json::Value::Null,
        },
        Opts::GetSubmissions { key, hex } => {
            let submissions = meta
                .module_api
                .get_submissions(key, meta.admin_auth()?)
                .await?;
            let submissions: serde_json::Map<String, serde_json::Value> = submissions
                .into_iter()
                .map(|(peer_id, value)| -> Result<_, CliCommandError> {
                    let value = if hex {
                        serde_json::Value::String(value.to_string())
                    } else {
                        serde_json::from_reader(value.as_slice())
                            .map_err(CliCommandError::SubmissionValueJson)?
                    };

                    Ok((peer_id.to_string(), value))
                })
                .collect::<Result<_, _>>()?;

            serde_json::Value::Object(submissions)
        }
        Opts::Submit { key, value, hex } => {
            let value: MetaValue = if hex {
                MetaValue::from_str(&value).map_err(CliCommandError::InvalidHexValue)?
            } else {
                let _valid_json: serde_json::Value =
                    serde_json::from_str(&value).map_err(CliCommandError::InvalidJsonValue)?;
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

/// A failure of a `meta` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    /// The federation did not serve the request.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The client has no admin credentials for a guardian-only request.
    #[error(transparent)]
    Admin(#[from] MetaAdminError),

    /// The consensus value is not valid JSON.
    #[error("deserializing consensus value as json")]
    ConsensusValueJson(#[source] serde_json::Error),

    /// A submitted value is not valid JSON.
    #[error("deserializing submission value")]
    SubmissionValueJson(#[source] serde_json::Error),

    /// The value to submit is not a valid hex string.
    #[error("value not a valid hex string")]
    InvalidHexValue(#[source] <MetaValue as FromStr>::Err),

    /// The value to submit is not a valid JSON string.
    #[error("value not a valid json string")]
    InvalidJsonValue(#[source] serde_json::Error),
}

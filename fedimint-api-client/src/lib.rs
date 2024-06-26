#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::time::Duration;

use anyhow::{bail, Context as _};
use api::{DynGlobalApi, FederationApiExt as _, WsFederationApi};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::backon;
use fedimint_core::NumPeers;
use query::FilterMap;
use tracing::debug;

pub mod api;
/// Client query system
pub mod query;

/// Tries to download the client config from the federation,
/// attempts to retry teb times before giving up.
pub async fn download_from_invite_code(invite_code: &InviteCode) -> anyhow::Result<ClientConfig> {
    debug!("Downloading client config from {:?}", invite_code);

    let federation_id = invite_code.federation_id();
    let api = DynGlobalApi::from_invite_code(invite_code);
    let api_secret = invite_code.api_secret();

    fedimint_core::util::retry(
        "Downloading client config",
        // 0.2, 0.2, 0.4, 0.6, 1.0, 1.6, ...
        // sum = 21.2
        backon::FibonacciBuilder::default()
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(5))
            .with_max_times(10),
        || try_download_client_config(&api, federation_id, api_secret.clone()),
    )
    .await
    .context("Failed to download client config")
}

/// Tries to download the client config only once.
pub async fn try_download_client_config(
    api: &DynGlobalApi,
    federation_id: FederationId,
    api_secret: Option<String>,
) -> anyhow::Result<ClientConfig> {
    let query_strategy = FilterMap::new(
        move |cfg: ClientConfig| {
            if federation_id != cfg.global.calculate_federation_id() {
                bail!("FederationId in invite code does not match client config")
            }

            Ok(cfg.global.api_endpoints)
        },
        NumPeers::from(1),
    );

    let api_endpoints = api
        .request_with_strategy(
            query_strategy,
            CLIENT_CONFIG_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
        )
        .await?;

    // now we can build an api for all guardians and download the client config
    let api_endpoints = api_endpoints
        .into_iter()
        .map(|(peer, url)| (peer, url.url))
        .collect();

    let client_config = WsFederationApi::new(api_endpoints, &api_secret)
        .request_current_consensus::<ClientConfig>(
            CLIENT_CONFIG_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
        )
        .await?;

    if client_config.calculate_federation_id() != federation_id {
        bail!("Obtained client config has different federation id");
    }

    Ok(client_config)
}

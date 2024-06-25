#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use anyhow::{bail, Context as _};
use api::net::Connector;
use api::{DynGlobalApi, FederationApiExt as _, WsFederationApi};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::backoff_util;
use fedimint_core::NumPeers;
use query::FilterMap;
use tracing::debug;

pub mod api;
/// Client query system
pub mod query;

impl Connector {
    /// Tries to download the [`ClientConfig`] from the federation with an
    /// specified [`Connector`] variant, attempts to retry ten times before
    /// giving up.
    pub async fn download_from_invite_code(
        &self,
        invite_code: &InviteCode,
    ) -> anyhow::Result<ClientConfig> {
        debug!("Downloading client config from {:?}", invite_code);

        let federation_id = invite_code.federation_id();
        // FIXME: (@leonardo) should fetch all the api_endpoints with proper
        // [`Connector`] too!
        let api = DynGlobalApi::from_invite_code(invite_code);
        let api_secret = invite_code.api_secret();

        fedimint_core::util::retry(
            "Downloading client config",
            backoff_util::aggressive_backoff(),
            || self.try_download_client_config(&api, federation_id, api_secret.clone()),
        )
        .await
        .context("Failed to download client config")
    }

    /// Tries to download the [`ClientConfig`] only once.
    pub async fn try_download_client_config(
        &self,
        api: &DynGlobalApi,
        federation_id: FederationId,
        api_secret: Option<String>,
    ) -> anyhow::Result<ClientConfig> {
        // TODO: use new download approach based on guardian PKs
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
        let api_endpoints = api_endpoints.into_iter().map(|(peer, url)| (peer, url.url));

        let client_config = WsFederationApi::new(self, api_endpoints, &api_secret)
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
}

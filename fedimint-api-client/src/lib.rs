#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use anyhow::{Context as _, bail};
use api::net::Connector;
use api::{DynGlobalApi, FederationApiExt as _, PeerError};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::backoff_util;
use fedimint_logging::LOG_CLIENT;
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
        invite: &InviteCode,
    ) -> anyhow::Result<(ClientConfig, DynGlobalApi)> {
        debug!(
            target: LOG_CLIENT,
            %invite,
            peers = ?invite.peers(),
            "Downloading client config via invite code"
        );

        let federation_id = invite.federation_id();
        let api_from_invite =
            DynGlobalApi::from_endpoints(invite.peers(), &invite.api_secret()).await?;
        let api_secret = invite.api_secret();

        fedimint_core::util::retry(
            "Downloading client config",
            backoff_util::aggressive_backoff(),
            || self.try_download_client_config(&api_from_invite, federation_id, api_secret.clone()),
        )
        .await
        .context("Failed to download client config")
    }

    /// Tries to download the [`ClientConfig`] only once.
    pub async fn try_download_client_config(
        &self,
        api_from_invite: &DynGlobalApi,
        federation_id: FederationId,
        api_secret: Option<String>,
    ) -> anyhow::Result<(ClientConfig, DynGlobalApi)> {
        debug!(target: LOG_CLIENT, "Downloading client config from peer");
        // TODO: use new download approach based on guardian PKs
        let query_strategy = FilterMap::new(move |cfg: ClientConfig| {
            if federation_id != cfg.global.calculate_federation_id() {
                return Err(PeerError::ConditionFailed(anyhow::anyhow!(
                    "FederationId in invite code does not match client config"
                )));
            }

            Ok(cfg.global.api_endpoints)
        });

        let api_endpoints = api_from_invite
            .request_with_strategy(
                query_strategy,
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        // now we can build an api for all guardians and download the client config
        let api_endpoints = api_endpoints.into_iter().map(|(peer, url)| (peer, url.url));

        debug!(target: LOG_CLIENT, "Verifying client config with all peers");

        let api_full = DynGlobalApi::from_endpoints(api_endpoints, &api_secret).await?;
        let client_config = api_full
            .request_current_consensus::<ClientConfig>(
                CLIENT_CONFIG_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;

        if client_config.calculate_federation_id() != federation_id {
            bail!("Obtained client config has different federation id");
        }

        Ok((client_config, api_full))
    }
}

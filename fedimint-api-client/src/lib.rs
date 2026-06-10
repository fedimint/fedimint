#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use anyhow::{Context as _, bail};
use api::{DynGlobalApi, FederationApiExt as _};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::backoff_util;
use fedimint_logging::LOG_CLIENT_NET;
use tracing::debug;

pub mod api;
pub mod metrics;
/// Client query system
pub mod query;

/// Tries to download the [`ClientConfig`], attempts to retry ten times before
/// giving up.
pub async fn download_from_invite_code(
    endpoints: &ConnectorRegistry,
    invite: &InviteCode,
) -> anyhow::Result<(ClientConfig, DynGlobalApi)> {
    debug!(
        target: LOG_CLIENT_NET,
        %invite,
        "Downloading client config via invite code"
    );

    let federation_id = invite.federation_id();
    let api_from_invite = DynGlobalApi::new(
        endpoints.clone(),
        invite.peers(),
        invite.api_secret().as_deref(),
    )?;
    let api_secret = invite.api_secret();
    let invite_id = invite.invite_id();
    let peer = invite.peer();

    fedimint_core::util::retry(
        "Downloading client config",
        backoff_util::aggressive_backoff(),
        || {
            try_download_client_config(
                endpoints,
                &api_from_invite,
                federation_id,
                api_secret.clone(),
                invite_id,
                peer,
            )
        },
    )
    .await
    .context("Failed to download client config")
}

/// Tries to download the [`ClientConfig`] only once.
pub async fn try_download_client_config(
    endpoints: &ConnectorRegistry,
    api_from_invite: &DynGlobalApi,
    federation_id: FederationId,
    api_secret: Option<String>,
    invite_id: Option<[u8; 16]>,
    peer: fedimint_core::PeerId,
) -> anyhow::Result<(ClientConfig, DynGlobalApi)> {
    debug!(target: LOG_CLIENT_NET, "Downloading client config from the guardian in the invite code");

    // The invite id is sent only to the guardian in the invite code; as its
    // issuer it counts the download towards the invite code's user limit
    let config = api_from_invite
        .request_single_peer::<ClientConfig>(
            CLIENT_CONFIG_ENDPOINT.to_owned(),
            ApiRequestErased::new(invite_id),
            peer,
        )
        .await?;

    if config.global.calculate_federation_id() != federation_id {
        bail!("FederationId in invite code does not match client config");
    }

    // now we can build an api for all guardians and download the client config
    let api_endpoints = config
        .global
        .api_endpoints
        .into_iter()
        .map(|(peer, url)| (peer, url.url))
        .collect();

    debug!(target: LOG_CLIENT_NET, "Verifying client config with all peers");

    let api_full = DynGlobalApi::new(endpoints.clone(), api_endpoints, api_secret.as_deref())?;
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

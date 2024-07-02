#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::time::Duration;

use anyhow::{bail, Context as _};
use api::{DynGlobalApi, FederationApiExt as _, WsFederationApi};
use bitcoin::secp256k1::rand::random;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey};
use fedimint_core::config::ClientConfig;
use fedimint_core::endpoint_constants::{CLIENT_CONFIG_ENDPOINT, CLIENT_CONFIG_SIGNATURE_ENDPOINT};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiRequest, ApiRequestErased};
use fedimint_core::util::backon;
use fedimint_core::{NumPeers, NumPeersExt, PeerId};
use query::FilterMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

pub mod api;
/// Client query system
pub mod query;

/// Tries to download the client config from the federation,
/// attempts to retry teb times before giving up.
pub async fn download_from_invite_code(invite_code: &InviteCode) -> anyhow::Result<ClientConfig> {
    debug!("Downloading client config from {:?}", invite_code);

    fedimint_core::util::retry(
        "Downloading client config",
        // 0.2, 0.2, 0.4, 0.6, 1.0, 1.6, ...
        // sum = 21.2
        backon::FibonacciBuilder::default()
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(5))
            .with_max_times(10),
        || try_download_client_config(invite_code),
    )
    .await
    .context("Failed to download client config")
}

/// Tries to download the client config only once.
pub async fn try_download_client_config(invite_code: &InviteCode) -> anyhow::Result<ClientConfig> {
    // we have to download the api endpoints first
    let federation_id = invite_code.federation_id();

    let query_strategy = FilterMap::new(
        move |cfg: ClientConfig, _| {
            if federation_id != cfg.global.calculate_federation_id() {
                bail!("FederationId in invite code does not match client config")
            }

            Ok(cfg.global.api_endpoints)
        },
        NumPeers::from(1),
    );

    let api_endpoints = DynGlobalApi::from_invite_code(invite_code)
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

    let api = WsFederationApi::new(api_endpoints, &invite_code.api_secret());

    let client_config = api
        .request_current_consensus::<ClientConfig>(
            CLIENT_CONFIG_ENDPOINT.to_owned(),
            ApiRequestErased::default(),
        )
        .await?;

    if client_config.global.broadcast_public_keys.is_none() {
        if client_config.calculate_federation_id() != federation_id {
            bail!("Obtained client config has different federation id");
        }
    } else {
        verify_client_config(&api, client_config.clone()).await?;
    }

    Ok(client_config)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigChallenge {
    nonce: [u8; 32],
}

impl ClientConfigChallenge {
    pub fn to_message(&self, client_config: &ClientConfig) -> Message {
        let client_config_str = serde_json::to_string(&client_config).unwrap();
        Message::from_slice(&[client_config_str.as_bytes(), self.nonce.as_slice()].concat())
            .unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigChallengeResponse {
    pub signature: Signature,
    pub serialized_config: Vec<u8>,
}

impl ClientConfigChallengeResponse {
    pub fn verify(
        &self,
        client_config: &ClientConfig,
        public_key: &PublicKey,
        message: &Message,
    ) -> anyhow::Result<()> {
        self.verify_against_client_config(client_config)?;
        self.verify_signature(public_key, message)?;
        Ok(())
    }

    pub fn verify_against_client_config(&self, client_config: &ClientConfig) -> anyhow::Result<()> {
        let deserialized_config = serde_json::from_slice::<ClientConfig>(&self.serialized_config)?;
        if deserialized_config != *client_config {
            bail!("Peer returned a different client config than the first guardian")
        }
        Ok(())
    }
    pub fn verify_signature(
        &self,
        public_key: &PublicKey,
        message: &Message,
    ) -> anyhow::Result<()> {
        self.signature
            .verify(&message, &public_key.x_only_public_key().0)?;

        Ok(())
    }
}

async fn verify_client_config(
    api: &WsFederationApi,
    client_config: ClientConfig,
) -> anyhow::Result<()> {
    let challenge = ClientConfigChallenge { nonce: random() };
    let challenge_clone = challenge.clone();
    let num_peers = client_config
        .global
        .broadcast_public_keys
        .as_ref()
        .expect("Client config has no broadcast keys")
        .to_num_peers();
    let query_strategy = FilterMap::new(
        move |cfg: ClientConfigChallengeResponse, peer| {
            verify_challenge_response(&client_config, cfg, peer, challenge.clone())
        },
        num_peers,
    );

    api.request_with_strategy(
        query_strategy,
        CLIENT_CONFIG_SIGNATURE_ENDPOINT.to_owned(),
        ApiRequest::new(challenge_clone),
    )
    .await?;

    Ok(())
}

fn verify_challenge_response(
    original_client_config: &ClientConfig,
    challenge_response: ClientConfigChallengeResponse,
    peer: PeerId,
    challenge: ClientConfigChallenge,
) -> anyhow::Result<()> {
    let peer_public_key = original_client_config
        .global
        .broadcast_public_keys
        .as_ref()
        .ok_or(anyhow::anyhow!(
            "Client config does not have broadcast public keys"
        ))?
        .get(&peer)
        .ok_or(anyhow::anyhow!(
            "Peer {peer} not found in client config broadcast public keys"
        ))?;
    challenge_response.verify(
        original_client_config,
        peer_public_key,
        &challenge.to_message(original_client_config),
    )?;

    Ok(())
}

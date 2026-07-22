use std::net::SocketAddr;

use anyhow::Context as _;
use fedimint_core::envs::{
    FM_IROH_DHT_ENABLE_ENV, FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_PUBLISHER_ENABLE_ENV,
    FM_IROH_PKARR_RESOLVER_ENABLE_ENV, FM_IROH_RELAYS_ENABLE_ENV, is_env_var_set,
    is_env_var_set_opt,
};
use fedimint_core::net::iroh::{IROH_IDLE_TIMEOUT, IROH_KEEP_ALIVE_INTERVAL};
use fedimint_core::secp256k1::SecretKey;
use fedimint_core::util::SafeUrl;
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_logging::LOG_NET_IROH;
use iroh_next::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh_next::endpoint::QuicTransportConfig;
use iroh_next::endpoint::presets::Minimal;
use iroh_next::{Endpoint, RelayMode};
use tracing::{debug, info, warn};

/// Child key used for the Iroh 1.0 API endpoint.
const IROH_V1_API_CHILD_ID: ChildId = ChildId(0);

/// Derive the Iroh 1.0 API secret key from the guardian broadcast key.
pub(crate) fn derive_iroh_v1_api_secret_key(broadcast_sk: &SecretKey) -> iroh_next::SecretKey {
    let root = DerivableSecret::new_root(&broadcast_sk.secret_bytes(), b"fedimint-iroh-next");
    let seed: [u8; 32] = root.child_key(IROH_V1_API_CHILD_ID).to_random_bytes();
    iroh_next::SecretKey::from_bytes(&seed)
}

/// Build an Iroh 1.0 server endpoint.
pub(crate) async fn build_iroh_v1_endpoint(
    secret_key: iroh_next::SecretKey,
    bind_addr: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    alpn: &[u8],
) -> anyhow::Result<Endpoint> {
    let relay_mode = if is_env_var_set_opt(FM_IROH_RELAYS_ENABLE_ENV).unwrap_or(true) {
        RelayMode::Default
    } else {
        warn!(target: LOG_NET_IROH, "Iroh 1.0 relays are disabled");
        RelayMode::Disabled
    };

    let mut builder = Endpoint::builder(Minimal);

    if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
        if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(PkarrPublisher::builder(iroh_dns.clone()));
        } else {
            warn!(target: LOG_NET_IROH, "Iroh 1.0 pkarr publisher is disabled");
        }

        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(PkarrResolver::builder(iroh_dns));
        } else {
            warn!(target: LOG_NET_IROH, "Iroh 1.0 pkarr resolver is disabled");
        }
    }

    if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
        debug!(target: LOG_NET_IROH, "Iroh 1.0 DHT is enabled");
        builder = builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
    } else {
        info!(target: LOG_NET_IROH, "Iroh 1.0 DHT is disabled");
    }

    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
        if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(PkarrPublisher::n0_dns());
        }
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());

        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(PkarrResolver::n0_dns());
        }
    } else {
        warn!(target: LOG_NET_IROH, "Iroh 1.0 n0 discovery is disabled");
    }

    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IROH_IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits in IdleTimeout"),
        ))
        .keep_alive_interval(IROH_KEEP_ALIVE_INTERVAL)
        .build();

    let endpoint = Box::pin(
        builder
            .relay_mode(relay_mode)
            .secret_key(secret_key)
            .alpns(vec![alpn.to_vec()])
            .transport_config(transport_config)
            .clear_ip_transports()
            .bind_addr(bind_addr)
            .context("Invalid Iroh 1.0 bind address")?
            .bind(),
    )
    .await
    .context("Failed to bind Iroh 1.0 endpoint")?;

    info!(
        target: LOG_NET_IROH,
        %bind_addr,
        endpoint_id = %endpoint.id(),
        endpoint_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
        "Iroh 1.0 API server endpoint"
    );

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1::SecretKey;

    use super::derive_iroh_v1_api_secret_key;

    #[test]
    fn iroh_v1_api_key_derivation_is_stable() {
        let broadcast_sk = SecretKey::from_slice(&[1; 32]).expect("valid test key");
        assert_eq!(
            derive_iroh_v1_api_secret_key(&broadcast_sk)
                .public()
                .to_string(),
            "e4b678498c23a7444ac2daf4aed336e88c2fa51c10e973f4ec57ae493e25fcf3"
        );
    }
}

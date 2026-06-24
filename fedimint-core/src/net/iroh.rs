use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::defaults::DEFAULT_STUN_PORT;
use iroh::discovery::pkarr::{PkarrPublisher, PkarrResolver};
use iroh::endpoint::{Builder, TransportConfig};
use iroh::{Endpoint, RelayMode, RelayNode, RelayUrl, SecretKey};
use iroh_relay::RelayQuicConfig;
use tracing::{info, warn};
use url::Url;

use crate::envs::{
    FM_IROH_DHT_ENABLE_ENV, FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_PUBLISHER_ENABLE_ENV,
    FM_IROH_PKARR_RESOLVER_ENABLE_ENV, FM_IROH_RELAYS_ENABLE_ENV, is_env_var_set,
    is_env_var_set_opt,
};

const DEFAULT_IROH_RELAYS: [&str; 2] = [
    "https://euc1-1.relay.elsirion.fedimint.iroh.link/",
    "https://use1-1.relay.elsirion.fedimint.iroh.link/",
];

/// QUIC idle timeout used for iroh API endpoints.
pub const IROH_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// QUIC keep-alive interval used for iroh API endpoints.
pub const IROH_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(not(target_family = "wasm"))]
pub async fn build_iroh_next_endpoint(
    secret_key: iroh_next::SecretKey,
    bind_addr: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    alpn: &[u8],
) -> Result<iroh_next::Endpoint, anyhow::Error> {
    let relay_mode = if !is_env_var_set_opt(FM_IROH_RELAYS_ENABLE_ENV).unwrap_or(true) {
        warn!(
            target: LOG_NET_IROH,
            "Iroh-next relays are disabled"
        );
        iroh_next::RelayMode::Disabled
    } else if iroh_relays.is_empty() {
        iroh_next::RelayMode::Default
    } else {
        iroh_next::RelayMode::custom(
            iroh_relays
                .into_iter()
                .map(|url| iroh_next::RelayUrl::from(url.to_unsafe())),
        )
    };

    let mut builder = iroh_next::Endpoint::builder(iroh_next::endpoint::presets::Minimal);

    if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
        if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(iroh_next::address_lookup::PkarrPublisher::builder(
                iroh_dns.clone(),
            ));
        } else {
            warn!(
                target: LOG_NET_IROH,
                "Iroh-next pkarr publisher is disabled"
            );
        }

        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            builder =
                builder.address_lookup(iroh_next::address_lookup::PkarrResolver::builder(iroh_dns));
        } else {
            warn!(
                target: LOG_NET_IROH,
                "Iroh-next pkarr resolver is disabled"
            );
        }
    }

    if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
        #[cfg(not(target_family = "wasm"))]
        {
            builder =
                builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
        }
    } else {
        info!(
            target: LOG_NET_IROH,
            "Iroh-next DHT is disabled"
        );
    }

    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
        builder = builder.address_lookup(iroh_next::address_lookup::DnsAddressLookup::n0_dns());
    } else {
        warn!(
            target: LOG_NET_IROH,
            "Iroh-next n0 discovery is disabled"
        );
    }

    let transport_config = iroh_next::endpoint::QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IROH_IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits in IdleTimeout"),
        ))
        .keep_alive_interval(IROH_KEEP_ALIVE_INTERVAL)
        .build();

    let endpoint = builder
        .relay_mode(relay_mode)
        .secret_key(secret_key)
        .alpns(vec![alpn.to_vec()])
        .transport_config(transport_config)
        .bind_addr(bind_addr)?
        .bind()
        .await
        .context("Failed to bind iroh-next endpoint")?;

    info!(
        target: LOG_NET_IROH,
        %bind_addr,
        node_id = %endpoint.id(),
        node_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
        "Iroh-next endpoint"
    );

    Ok(endpoint)
}

pub async fn build_iroh_endpoint(
    secret_key: SecretKey,
    bind_addr: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    alpn: &[u8],
) -> Result<Endpoint, anyhow::Error> {
    let relay_mode = if !is_env_var_set_opt(FM_IROH_RELAYS_ENABLE_ENV).unwrap_or(true) {
        warn!(
            target: LOG_NET_IROH,
            "Iroh relays are disabled"
        );
        RelayMode::Disabled
    } else if iroh_relays.is_empty() {
        RelayMode::Custom(
            DEFAULT_IROH_RELAYS
                .into_iter()
                .map(|url| {
                    relay_node_from_url(Url::parse(url).expect("default Iroh relay URL is valid"))
                })
                .collect(),
        )
    } else {
        RelayMode::Custom(
            iroh_relays
                .into_iter()
                .map(|url| relay_node_from_url(url.to_unsafe()))
                .collect(),
        )
    };

    let mut builder = Endpoint::builder();

    if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
        if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.add_discovery({
                let iroh_dns = iroh_dns.clone();
                move |sk: &SecretKey| Some(PkarrPublisher::new(sk.clone(), iroh_dns))
            });
        } else {
            warn!(
                target: LOG_NET_IROH,
                "Iroh pkarr publisher is disabled"
            );
        }

        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
        } else {
            warn!(
                target: LOG_NET_IROH,
                "Iroh pkarr resolver is disabled"
            );
        }
    }

    // See <https://github.com/fedimint/fedimint/issues/7811>
    if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
        #[cfg(not(target_family = "wasm"))]
        {
            tracing::debug!(
                target: LOG_NET_IROH,
                "Iroh DHT is enabled"
            );
            builder = builder.discovery_dht();
        }
    } else {
        info!(
            target: LOG_NET_IROH,
            "Iroh DHT is disabled"
        );
    }

    builder = add_n0_discovery(builder);

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        IROH_IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits in IdleTimeout"),
    ));
    // Iroh's default builder sets keep_alive_interval to 1s, but since we're
    // providing a custom TransportConfig we need to set it explicitly.
    transport_config.keep_alive_interval(Some(IROH_KEEP_ALIVE_INTERVAL));

    let builder = builder
        .relay_mode(relay_mode)
        .secret_key(secret_key)
        .alpns(vec![alpn.to_vec()])
        .transport_config(transport_config);

    let builder = match bind_addr {
        SocketAddr::V4(addr_v4) => builder.bind_addr_v4(addr_v4),
        SocketAddr::V6(addr_v6) => builder.bind_addr_v6(addr_v6),
    };

    let endpoint = Box::pin(builder.bind())
        .await
        .context("Failed to bind Iroh endpoint")?;

    info!(
        target: LOG_NET_IROH,
        %bind_addr,
        node_id = %endpoint.node_id(),
        node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
        "Iroh p2p server endpoint"
    );

    Ok(endpoint)
}

fn relay_node_from_url(url: Url) -> RelayNode {
    RelayNode {
        url: RelayUrl::from(url),
        stun_only: false,
        stun_port: DEFAULT_STUN_PORT,
        quic: Some(RelayQuicConfig::default()),
    }
}

fn add_n0_discovery(builder: Builder) -> Builder {
    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
        return add_n0_pkarr_resolver(builder.discovery_n0());
    }

    warn!(target: LOG_NET_IROH, "Iroh n0 discovery is disabled");
    builder
}

#[cfg(not(target_family = "wasm"))]
fn add_n0_pkarr_resolver(builder: Builder) -> Builder {
    // Native discovery_n0 only uses DNS TXT; add HTTPS pkarr fallback.
    if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
        return builder.add_discovery(|_| Some(PkarrResolver::n0_dns()));
    }

    warn!(
        target: LOG_NET_IROH,
        "Iroh pkarr resolver is disabled"
    );
    builder
}

#[cfg(target_family = "wasm")]
fn add_n0_pkarr_resolver(builder: Builder) -> Builder {
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_iroh_relays_are_valid_urls() {
        for relay in DEFAULT_IROH_RELAYS {
            Url::parse(relay).expect("default Iroh relay URL is valid");
        }
    }
}

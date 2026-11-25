//! Guardian P2P endpoint construction for Iroh 1.0.
//!
//! This server-private builder is intentionally additive. The shared
//! `fedimint_core::net::iroh` builder remains on Iroh 0.35 for guardian API and
//! gateway callers while guardian P2P migrates independently.

use std::borrow::Cow;
use std::net::SocketAddr;

use anyhow::Context as _;
use fedimint_connectors::iroh::default_iroh_v1_relay_mode;
use fedimint_core::envs::{
    FM_IROH_DHT_ENABLE_ENV, FM_IROH_N0_DISCOVERY_ENABLE_ENV, FM_IROH_PKARR_PUBLISHER_ENABLE_ENV,
    FM_IROH_PKARR_RESOLVER_ENABLE_ENV, FM_IROH_RELAYS_ENABLE_ENV, is_env_var_set,
    is_env_var_set_opt,
};
use fedimint_core::net::iroh::{IROH_IDLE_TIMEOUT, IROH_KEEP_ALIVE_INTERVAL};
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh_next::address_lookup::{AddrFilter, DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh_next::endpoint::presets::Minimal;
use iroh_next::endpoint::{Builder, QuicTransportConfig};
use iroh_next::{Endpoint, RelayMode, RelayUrl, SecretKey, TransportAddr};
use tracing::{debug, info, warn};

use crate::net::iroh::configure_iroh_ip_transports;

/// Iroh before 1.5 dialed the relay at `/relay` whatever path its URL had,
/// while 1.5 keeps the path and appends `relay` to it, so a URL with a path
/// now reaches a different place than it did before the upgrade.
fn warn_on_relay_path(url: &SafeUrl) {
    if !matches!(url.path(), "" | "/") {
        warn!(
            target: LOG_NET_IROH,
            %url,
            "Iroh relay URL has a path, which Iroh 1.5 keeps and appends `relay` to; \
             configure the relay's origin if it is served at `/relay`"
        );
    }
}

/// Build and bind an Iroh 1.0 endpoint using guardian P2P policy.
pub(super) async fn build_iroh_endpoint(
    secret_key: SecretKey,
    bind_addr: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    alpn: &[u8],
) -> anyhow::Result<Endpoint> {
    let relay_mode = if !is_env_var_set_opt(FM_IROH_RELAYS_ENABLE_ENV).unwrap_or(true) {
        warn!(target: LOG_NET_IROH, "Iroh relays are disabled");
        RelayMode::Disabled
    } else if iroh_relays.is_empty() {
        default_iroh_v1_relay_mode()
    } else {
        RelayMode::Custom(
            iroh_relays
                .into_iter()
                .inspect(warn_on_relay_path)
                .map(|url| RelayUrl::from(url.to_unsafe()))
                .collect(),
        )
    };

    let mut builder = Endpoint::builder(Minimal);

    if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
        if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(
                PkarrPublisher::builder(iroh_dns.clone()).addr_filter(guardian_pkarr_addr_filter()),
            );
        } else {
            warn!(target: LOG_NET_IROH, "Iroh pkarr publisher is disabled");
        }

        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            builder = builder.address_lookup(PkarrResolver::builder(iroh_dns));
        } else {
            warn!(target: LOG_NET_IROH, "Iroh pkarr resolver is disabled");
        }
    }

    if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
        debug!(target: LOG_NET_IROH, "Iroh DHT is enabled");
        builder = builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
    } else {
        info!(target: LOG_NET_IROH, "Iroh DHT is disabled");
    }

    builder = add_n0_discovery(builder);

    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(
            IROH_IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits in IdleTimeout"),
        ))
        .keep_alive_interval(IROH_KEEP_ALIVE_INTERVAL)
        .build();

    let endpoint = Box::pin(
        configure_iroh_ip_transports(
            builder
                .relay_mode(relay_mode)
                .secret_key(secret_key)
                .alpns(vec![alpn.to_vec()])
                .transport_config(transport_config),
            bind_addr,
        )?
        .bind(),
    )
    .await
    .context("Failed to bind Iroh endpoint")?;

    info!(
        target: LOG_NET_IROH,
        %bind_addr,
        endpoint_id = %endpoint.id(),
        endpoint_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
        "Iroh P2P server endpoint"
    );

    Ok(endpoint)
}

fn add_n0_discovery(mut builder: Builder) -> Builder {
    if !is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
        warn!(target: LOG_NET_IROH, "Iroh n0 discovery is disabled");
        return builder;
    }

    // Publish our address as well as resolving peer addresses. Starting from
    // `Minimal` installs neither half automatically.
    builder = builder
        .address_lookup(PkarrPublisher::n0_dns().addr_filter(guardian_pkarr_addr_filter()))
        .address_lookup(DnsAddressLookup::n0_dns());

    if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
        builder.address_lookup(PkarrResolver::n0_dns())
    } else {
        warn!(target: LOG_NET_IROH, "Iroh pkarr resolver is disabled");
        builder
    }
}

/// Preserve Iroh 0.35's Pkarr publication policy for guardian connectivity.
///
/// Prefer relays when available to avoid publishing direct IP addresses. When
/// no relay is available, direct addresses must be published so relay-disabled
/// guardians remain discoverable by endpoint ID.
pub(super) fn guardian_pkarr_addr_filter() -> AddrFilter {
    AddrFilter::new(|addrs| {
        let publish_relay = addrs.iter().any(TransportAddr::is_relay);
        Cow::Owned(
            addrs
                .iter()
                .filter(|addr| {
                    if publish_relay {
                        addr.is_relay()
                    } else {
                        matches!(addr, TransportAddr::Ip(_))
                    }
                })
                .cloned()
                .collect(),
        )
    })
}

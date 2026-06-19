use std::time::Duration;

/// QUIC idle timeout used for iroh API endpoints.
pub const IROH_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// QUIC keep-alive interval used for iroh API endpoints.
pub const IROH_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);

// The iroh server endpoint is only ever built on native targets; wasm clients
// only need the timeout constants above.
#[cfg(not(target_family = "wasm"))]
pub use server::build_iroh_endpoint;

#[cfg(not(target_family = "wasm"))]
mod server {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use anyhow::Context;
    use fedimint_core::util::SafeUrl;
    use fedimint_logging::LOG_NET_IROH;
    use iroh_next::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
    use iroh_next::endpoint::presets::Minimal;
    use iroh_next::endpoint::{Builder, QuicTransportConfig};
    use iroh_next::{Endpoint, RelayMode, RelayUrl, SecretKey};
    use tracing::{debug, info, warn};

    use super::{IROH_IDLE_TIMEOUT, IROH_KEEP_ALIVE_INTERVAL};
    use crate::envs::{
        FM_IROH_DHT_ENABLE_ENV, FM_IROH_N0_DISCOVERY_ENABLE_ENV,
        FM_IROH_PKARR_PUBLISHER_ENABLE_ENV, FM_IROH_PKARR_RESOLVER_ENABLE_ENV,
        FM_IROH_RELAYS_ENABLE_ENV, is_env_var_set, is_env_var_set_opt,
    };

    // The fedimint-operated relays still run iroh 0.35 and are not protocol
    // compatible with the 1.0 endpoint, so we fall back to iroh's default
    // (n0) relays instead. Start using this list again once the relays are
    // upgraded.
    #[allow(dead_code)]
    const DEFAULT_IROH_RELAYS: [&str; 2] = [
        "https://euc1-1.relay.elsirion.fedimint.iroh.link/",
        "https://use1-1.relay.elsirion.fedimint.iroh.link/",
    ];

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
            // Use iroh's default (n0) relays, which run a 1.0-compatible relay.
            // TODO: switch back to `RelayMode::Custom(DEFAULT_IROH_RELAYS)` once
            // the fedimint-operated relays are upgraded to iroh 1.0.
            RelayMode::Default
        } else {
            RelayMode::Custom(
                iroh_relays
                    .into_iter()
                    .map(|url| {
                        RelayUrl::from_str(url.as_str())
                            .expect("configured Iroh relay URL is valid")
                    })
                    .collect(),
            )
        };

        let mut builder = Endpoint::builder(Minimal);

        if let Some(iroh_dns) = iroh_dns.map(SafeUrl::to_unsafe) {
            if is_env_var_set_opt(FM_IROH_PKARR_PUBLISHER_ENABLE_ENV).unwrap_or(true) {
                builder = builder.address_lookup(PkarrPublisher::builder(iroh_dns.clone()));
            } else {
                warn!(
                    target: LOG_NET_IROH,
                    "Iroh pkarr publisher is disabled"
                );
            }

            if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
                builder = builder.address_lookup(PkarrResolver::builder(iroh_dns));
            } else {
                warn!(
                    target: LOG_NET_IROH,
                    "Iroh pkarr resolver is disabled"
                );
            }
        }

        // See <https://github.com/fedimint/fedimint/issues/7811>
        if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
            debug!(
                target: LOG_NET_IROH,
                "Iroh DHT is enabled"
            );
            builder =
                builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
        } else {
            info!(
                target: LOG_NET_IROH,
                "Iroh DHT is disabled"
            );
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
            builder
                .relay_mode(relay_mode)
                .secret_key(secret_key)
                .alpns(vec![alpn.to_vec()])
                .transport_config(transport_config)
                .bind_addr(bind_addr)
                .context("Invalid Iroh bind address")?
                .bind(),
        )
        .await
        .context("Failed to bind Iroh endpoint")?;

        info!(
            target: LOG_NET_IROH,
            %bind_addr,
            node_id = %endpoint.id(),
            node_id_pkarr = %z32::encode(endpoint.id().as_bytes()),
            "Iroh p2p server endpoint"
        );

        Ok(endpoint)
    }

    fn add_n0_discovery(builder: Builder) -> Builder {
        if !is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
            warn!(target: LOG_NET_IROH, "Iroh n0 discovery is disabled");
            return builder;
        }

        // Publish our address to n0's DNS pkarr relay so peers can discover us,
        // and resolve peers via n0 DNS.
        let builder = builder
            .address_lookup(PkarrPublisher::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns());

        add_n0_pkarr_resolver(builder)
    }

    fn add_n0_pkarr_resolver(builder: Builder) -> Builder {
        // n0 discovery only resolves via DNS TXT natively; add the HTTPS pkarr
        // fallback as well.
        if is_env_var_set_opt(FM_IROH_PKARR_RESOLVER_ENABLE_ENV).unwrap_or(true) {
            return builder.address_lookup(PkarrResolver::n0_dns());
        }

        warn!(
            target: LOG_NET_IROH,
            "Iroh pkarr resolver is disabled"
        );
        builder
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn default_iroh_relays_are_valid_urls() {
            for relay in DEFAULT_IROH_RELAYS {
                RelayUrl::from_str(relay).expect("default Iroh relay URL is valid");
            }
        }
    }
}

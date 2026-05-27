use std::net::SocketAddr;

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::defaults::DEFAULT_STUN_PORT;
use iroh::discovery::pkarr::{PkarrPublisher, PkarrResolver};
use iroh::{Endpoint, RelayMode, RelayNode, RelayUrl, SecretKey};
use iroh_relay::RelayQuicConfig;
use tracing::{debug, info, warn};
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
            debug!(
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

    if is_env_var_set_opt(FM_IROH_N0_DISCOVERY_ENABLE_ENV).unwrap_or(true) {
        builder = builder.discovery_n0();
    } else {
        warn!(
            target: LOG_NET_IROH,
            "Iroh n0 discovery is disabled"
        );
    }

    let builder = builder
        .relay_mode(relay_mode)
        .secret_key(secret_key)
        .alpns(vec![alpn.to_vec()]);

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

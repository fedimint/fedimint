use std::net::SocketAddr;

use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::defaults::DEFAULT_STUN_PORT;
use iroh::discovery::pkarr::{PkarrPublisher, PkarrResolver};
use iroh::{Endpoint, RelayMode, RelayNode, RelayUrl, SecretKey};
use iroh_relay::RelayQuicConfig;
use tracing::info;
use url::Url;

use crate::envs::{FM_IROH_ENABLE_DHT_ENV, is_env_var_set};
use crate::iroh_prod::{FM_IROH_DNS_FEDIMINT_PROD, FM_IROH_RELAYS_FEDIMINT_PROD};

pub async fn build_iroh_endpoint(
    secret_key: SecretKey,
    bind_addr: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    alpn: &[u8],
) -> Result<Endpoint, anyhow::Error> {
    let iroh_dns_servers: Vec<_> = iroh_dns.clone().map_or_else(
        || {
            FM_IROH_DNS_FEDIMINT_PROD
                .into_iter()
                .map(|dns| dns.parse().expect("Can't fail"))
                .collect()
        },
        |iroh_dns| vec![iroh_dns.to_unsafe()],
    );

    let relay_mode = if iroh_relays.is_empty() {
        RelayMode::Custom(
            FM_IROH_RELAYS_FEDIMINT_PROD
                .into_iter()
                .map(|url| RelayNode {
                    url: RelayUrl::from(Url::parse(url).expect("Hardcoded, can't fail")),
                    stun_only: false,
                    stun_port: DEFAULT_STUN_PORT,
                    quic: Some(RelayQuicConfig::default()),
                })
                .collect(),
        )
    } else {
        RelayMode::Custom(
            iroh_relays
                .into_iter()
                .map(|url| RelayNode {
                    url: RelayUrl::from(url.to_unsafe()),
                    stun_only: false,
                    stun_port: DEFAULT_STUN_PORT,
                    quic: Some(RelayQuicConfig::default()),
                })
                .collect(),
        )
    };

    let mut builder = Endpoint::builder();

    for iroh_dns in iroh_dns_servers {
        builder = builder
            .add_discovery({
                let iroh_dns = iroh_dns.clone();
                move |sk: &SecretKey| Some(PkarrPublisher::new(sk.clone(), iroh_dns))
            })
            .add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
    }

    // See <https://github.com/fedimint/fedimint/issues/7811>
    if is_env_var_set(FM_IROH_ENABLE_DHT_ENV) {
        #[cfg(not(target_family = "wasm"))]
        {
            builder = builder.discovery_dht();
        }
    } else {
        info!(
            target: LOG_NET_IROH,
            "Iroh DHT is disabled"
        );
    }

    let builder = builder
        .discovery_n0()
        .relay_mode(relay_mode)
        .secret_key(secret_key)
        .alpns(vec![alpn.to_vec()]);

    let builder = match bind_addr {
        SocketAddr::V4(addr_v4) => builder.bind_addr_v4(addr_v4),
        SocketAddr::V6(addr_v6) => builder.bind_addr_v6(addr_v6),
    };

    let endpoint = builder.bind().await.expect("Could not bind to port");

    info!(
        target: LOG_NET_IROH,
        %bind_addr,
        node_id = %endpoint.node_id(),
        node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
        "Iroh p2p server endpoint"
    );

    Ok(endpoint)
}

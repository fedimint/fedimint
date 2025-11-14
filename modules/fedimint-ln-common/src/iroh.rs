use std::collections::BTreeMap;

use fedimint_core::envs::{FM_IROH_DHT_ENABLE_ENV, is_env_var_set};
use fedimint_core::iroh_prod::FM_IROH_DNS_FEDIMINT_PROD;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::discovery::pkarr::PkarrResolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId};
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

pub const FEDIMINT_GATEWAY_ALPN: &[u8] = b"FEDIMINT_GATEWAY_ALPN";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrohGatewayRequest {
    /// REST API route for specifying which action to take
    pub route: String,

    /// Parameters for the request
    pub params: Option<serde_json::Value>,

    /// Password for authenticated requests to the gateway
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrohGatewayResponse {
    pub status: u16,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct GatewayIrohConnector {
    node_id: iroh::NodeId,
    endpoint: Endpoint,
    password: Option<String>,
    connection_overrides: BTreeMap<NodeId, NodeAddr>,
}

impl GatewayIrohConnector {
    pub async fn new(
        iroh_pk: iroh::PublicKey,
        password: Option<String>,
        iroh_dns: Option<SafeUrl>,
    ) -> anyhow::Result<Self> {
        let mut builder = Endpoint::builder();

        let iroh_dns_servers: Vec<_> = iroh_dns.map_or_else(
            || {
                FM_IROH_DNS_FEDIMINT_PROD
                    .into_iter()
                    .map(|url| {
                        SafeUrl::parse(url)
                            .expect("Hardcoded, can't fail")
                            .to_unsafe()
                    })
                    .collect()
            },
            |url| vec![url.to_unsafe()],
        );

        for iroh_dns in iroh_dns_servers {
            builder = builder.add_discovery(|_| Some(PkarrResolver::new(iroh_dns)));
        }

        // As a client, we don't need to register on any relays
        let mut builder = builder.relay_mode(iroh::RelayMode::Disabled);

        // See <https://github.com/fedimint/fedimint/issues/7811>
        if is_env_var_set(FM_IROH_DHT_ENABLE_ENV) {
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

        // instead of `.discovery_n0`, which brings publisher we don't want
        {
            #[cfg(target_family = "wasm")]
            {
                builder = builder.add_discovery(move |_| Some(PkarrResolver::n0_dns()));
            }

            #[cfg(not(target_family = "wasm"))]
            {
                builder = builder
                    .add_discovery(move |_| Some(iroh::discovery::dns::DnsDiscovery::n0_dns()));
            }
        }

        let endpoint = builder.bind().await?;

        Ok(Self {
            node_id: iroh_pk,
            endpoint,
            password,
            connection_overrides: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn with_connection_override(mut self, node: NodeId, addr: NodeAddr) -> Self {
        self.connection_overrides.insert(node, addr);
        self
    }

    async fn connect(&self) -> anyhow::Result<Connection> {
        let connection = match self.connection_overrides.get(&self.node_id) {
            Some(node_addr) => {
                trace!(target: LOG_NET_IROH, node_id = %self.node_id, "Using a connectivity override for connection");
                self.endpoint
                    .connect(node_addr.clone(), FEDIMINT_GATEWAY_ALPN)
                    .await?
            }
            None => {
                self.endpoint
                    .connect(self.node_id, FEDIMINT_GATEWAY_ALPN)
                    .await?
            }
        };

        // TODO: Spawn connection monitoring?
        Ok(connection)
    }

    pub async fn request(
        &self,
        route: &str,
        payload: Option<serde_json::Value>,
    ) -> anyhow::Result<IrohGatewayResponse> {
        let iroh_request = IrohGatewayRequest {
            route: route.to_string(),
            params: payload,
            password: self.password.clone(),
        };
        let json = serde_json::to_vec(&iroh_request).expect("serialization cant fail");
        let connection = self.connect().await?;
        let (mut sink, mut stream) = connection.open_bi().await?;
        sink.write_all(&json).await?;
        sink.finish()?;
        let response = stream.read_to_end(1_000_000).await?;
        let iroh_response = serde_json::from_slice::<IrohGatewayResponse>(&response)?;
        Ok(iroh_response)
    }
}

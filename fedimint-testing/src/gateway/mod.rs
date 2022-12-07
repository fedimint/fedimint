use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::secp256k1;
use bitcoin::KeyPair;
use fedimint_api::config::ClientConfig;
use fedimint_api::task::TaskGroup;
use fedimint_ln::LightningGateway;
use ln_gateway::actor::GatewayActor;
use ln_gateway::client::{GatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder};
use ln_gateway::config::GatewayConfig;
use ln_gateway::rpc::GatewayRequest;
use ln_gateway::LnGateway;
use mint_client::{FederationId, GatewayClient, GatewayClientConfig};
use rand::rngs::OsRng;
use url::Url;

use crate::user::UserTest;
use crate::utils::LnRpcAdapter;

pub struct GatewayTest {
    pub actor: Arc<GatewayActor>,
    pub adapter: Arc<LnRpcAdapter>,
    pub keys: LightningGateway,
    pub user: UserTest<GatewayClientConfig>,
    pub client: Arc<GatewayClient>,
}

impl GatewayTest {
    pub async fn new(
        ln_client_adapter: LnRpcAdapter,
        client_config: ClientConfig,
        node_pub_key: secp256k1::PublicKey,
        bind_port: u16,
    ) -> Self {
        let mut rng = OsRng;
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut rng);

        let keys = LightningGateway {
            mint_pub_key: kp.x_only_public_key().0,
            node_pub_key,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
        };

        let bind_addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
        let announce_addr = Url::parse(format!("http://{}", bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint");
        let gw_client_cfg = GatewayClientConfig {
            client_config: client_config.clone(),
            redeem_key: kp,
            timelock_delta: 10,
            api: announce_addr.clone(),
            node_pub_key,
        };

        // Create federation client builder for the gateway
        let client_builder: GatewayClientBuilder =
            StandardGatewayClientBuilder::new(PathBuf::new(), MemDbFactory.into()).into();

        let (sender, receiver) = tokio::sync::mpsc::channel::<GatewayRequest>(100);
        let adapter = Arc::new(ln_client_adapter);
        let ln_rpc = Arc::clone(&adapter);

        let gw_cfg = GatewayConfig {
            bind_address: bind_addr,
            announce_address: announce_addr,
            password: "abc".into(),
            default_federation: FederationId(gw_client_cfg.client_config.federation_name.clone()),
        };

        let gateway = LnGateway::new(
            gw_cfg,
            ln_rpc,
            client_builder.clone(),
            sender,
            receiver,
            TaskGroup::new(),
        )
        .await;

        let client = Arc::new(
            client_builder
                .build(gw_client_cfg.clone())
                .await
                .expect("Could not build gateway client"),
        );

        let actor = gateway
            .register_federation(client.clone())
            .await
            .expect("Could not register federation");
        // Note: We don't run the gateway in test scenarios

        // Create a user test from gateway federation client
        let user = UserTest::new(client.clone());

        GatewayTest {
            actor,
            adapter,
            keys,
            user,
            client,
        }
    }
}

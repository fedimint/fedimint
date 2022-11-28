use async_trait::async_trait;
use bitcoin::{secp256k1, KeyPair};
use fedimint_api::{
    config::ClientConfig,
    db::{mem_impl::MemDatabase, Database},
};
use ln_gateway::{client::IGatewayClientBuilder, LnGatewayError};
use mint_client::{
    api::{FederationApi, WsFederationConnect},
    Client, FederationId, GatewayClient, GatewayClientConfig,
};
use secp256k1::{PublicKey, Secp256k1};
use url::Url;

use super::fed::FakeApi;

#[derive(Debug, Clone)]
pub struct TestGatewayClientBuilder {}

#[async_trait]
impl IGatewayClientBuilder for TestGatewayClientBuilder {
    fn build(
        &self,
        config: GatewayClientConfig,
    ) -> Result<Client<GatewayClientConfig>, LnGatewayError> {
        let federation_id = FederationId(config.client_config.federation_name.clone());

        let api: FederationApi = FakeApi::new().into();
        let db = self.create_database(federation_id)?;

        Ok(GatewayClient::new_with_api(
            config,
            db,
            api,
            Default::default(),
        ))
    }

    fn create_database(&self, _federation_id: FederationId) -> Result<Database, LnGatewayError> {
        Ok(MemDatabase::new().into())
    }

    async fn create_config(
        &self,
        _connect: WsFederationConnect,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig, LnGatewayError> {
        // TODO: Instead of using a live `WsFederationApi` from `WsFederationConnect`,
        // we should use `FakeFed` to mock websocket request to fetch client config.
        // See Issue #545
        let client_config = ClientConfig {
            federation_name: "".to_string(),
            nodes: [].into(),
            modules: [].into(),
        };

        let mut rng = rand::rngs::OsRng;
        let ctx = Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        Ok(GatewayClientConfig {
            client_config,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key: node_pubkey,
            api: announce_address,
        })
    }

    fn save_config(&self, _config: GatewayClientConfig) -> Result<(), LnGatewayError> {
        unimplemented!()
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>, LnGatewayError> {
        Ok([].into())
    }
}

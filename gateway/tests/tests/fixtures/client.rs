use std::path::PathBuf;

use async_trait::async_trait;
use bitcoin::{secp256k1, KeyPair};
use fedimint_api::config::{ClientConfig, FederationId};
use ln_gateway::{
    client::{DynDbFactory, IGatewayClientBuilder},
    LnGatewayError,
};
use mint_client::{
    api::{DynFederationApi, WsFederationConnect},
    module_decode_stubs, Client, GatewayClient, GatewayClientConfig,
};
use secp256k1::{PublicKey, Secp256k1};
use url::Url;

use super::fed::MockApi;

#[derive(Debug, Clone)]
pub struct TestGatewayClientBuilder {
    db_factory: DynDbFactory,
}

impl TestGatewayClientBuilder {
    pub fn new(db_factory: DynDbFactory) -> Self {
        Self { db_factory }
    }
}

#[async_trait]
impl IGatewayClientBuilder for TestGatewayClientBuilder {
    async fn build(
        &self,
        config: GatewayClientConfig,
    ) -> Result<Client<GatewayClientConfig>, LnGatewayError> {
        let federation_id = config.client_config.federation_id.clone();

        let api: DynFederationApi = MockApi::new().into();
        let db = self.db_factory.create_database(
            federation_id,
            PathBuf::new(),
            module_decode_stubs(),
        )?;

        Ok(GatewayClient::new_with_api(config, db, api, Default::default()).await)
    }

    async fn create_config(
        &self,
        _connect: WsFederationConnect,
        mint_channel_id: u64,
        node_pubkey: PublicKey,
        announce_address: Url,
    ) -> Result<GatewayClientConfig, LnGatewayError> {
        // TODO: use the connect info urls to get the federation name?
        // Simulate clients in the same federation by seeding the generated `client_config`
        // Using some of the info in provided web socket connect info
        let auth_pk = threshold_crypto::SecretKey::random().public_key();
        let client_config = ClientConfig {
            federation_name: "".to_string(),
            federation_id: FederationId(auth_pk),
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            auth_pk,
            nodes: [].into(),
            modules: [].into(),
        };

        let mut rng = rand::rngs::OsRng;
        let ctx = Secp256k1::new();
        let kp_fed = KeyPair::new(&ctx, &mut rng);

        Ok(GatewayClientConfig {
            mint_channel_id,
            client_config,
            redeem_key: kp_fed,
            timelock_delta: 10,
            node_pub_key: node_pubkey,
            api: announce_address,
        })
    }

    fn save_config(&self, _config: GatewayClientConfig) -> Result<(), LnGatewayError> {
        // noop: don't save configs
        Ok(())
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>, LnGatewayError> {
        // noop: return empty config list
        Ok([].into())
    }
}

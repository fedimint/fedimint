use std::collections::BTreeSet;
use std::default::Default;
use std::path::PathBuf;

use async_trait::async_trait;
use bitcoin::{secp256k1, KeyPair};
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client_legacy::{module_decode_stubs, Client, GatewayClient, GatewayClientConfig};
use fedimint_core::api::{DynGlobalApi, WsClientConnectInfo};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::PeerId;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::client::{DynDbFactory, IGatewayClientBuilder};
use ln_gateway::GatewayError;
use secp256k1::{PublicKey, Secp256k1};
use url::Url;

use super::fed::MockApi;

#[derive(Debug, Clone)]
pub struct TestGatewayClientBuilder {
    db_factory: DynDbFactory,
    gateway_api: Url,
}

impl TestGatewayClientBuilder {
    pub fn new(db_factory: DynDbFactory, gateway_api: Url) -> Self {
        Self {
            db_factory,
            gateway_api,
        }
    }
}

#[async_trait]
impl IGatewayClientBuilder for TestGatewayClientBuilder {
    async fn build(
        &self,
        config: GatewayClientConfig,
        decoders: ModuleDecoderRegistry,
        _module_gens: ClientModuleGenRegistry,
    ) -> Result<Client<GatewayClientConfig>, GatewayError> {
        let federation_id = config.client_config.federation_id;
        // Ignore `config`s, hardcode one peer.
        let members = BTreeSet::from([PeerId::from(0)]);

        let api: DynGlobalApi = MockApi::make_test_fed(LEGACY_HARDCODED_INSTANCE_ID_LN, members)
            .await
            .into();
        let db = self.db_factory.create_database(
            federation_id,
            PathBuf::new(),
            module_decode_stubs(),
        )?;

        Ok(GatewayClient::new_with_api(
            config,
            decoders,
            Default::default(),
            db,
            api,
            Default::default(),
        )
        .await)
    }

    async fn create_config(
        &self,
        _connect: WsClientConnectInfo,
        mint_channel_id: u64,
        node_pubkey: PublicKey,
        _module_gens: ClientModuleGenRegistry,
        fees: RoutingFees,
    ) -> Result<GatewayClientConfig, GatewayError> {
        // TODO: use the connect info urls to get the federation name?
        // Simulate clients in the same federation by seeding the generated
        // `client_config` Using some of the info in provided web socket connect
        // info
        let auth_pk = threshold_crypto::SecretKey::random().public_key();
        let client_config = ClientConfig {
            federation_id: FederationId(auth_pk),
            epoch_pk: threshold_crypto::SecretKey::random().public_key(),
            api_endpoints: [].into(),
            modules: [].into(),
            meta: Default::default(),
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
            api: self.gateway_api.clone(),
            fees,
        })
    }

    fn save_config(&self, _config: GatewayClientConfig) -> Result<(), GatewayError> {
        // noop: don't save configs
        Ok(())
    }

    fn load_configs(&self) -> Result<Vec<GatewayClientConfig>, GatewayError> {
        // noop: return empty config list
        Ok([].into())
    }
}

mod api;
pub mod clients;
pub mod ln;
pub mod mint;
pub mod wallet;

use crate::api::FederationApi;
use crate::ln::gateway::LightningGateway;
pub use clients::user::UserClient;
use minimint::config::ClientConfig;
use minimint_api::db::Database;
use serde::{Deserialize, Serialize};

pub struct BorrowedClientContext<'a, C> {
    config: &'a C,
    db: &'a dyn Database,
    api: &'a dyn FederationApi,
    secp: &'a secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

struct OwnedClientContext<C> {
    config: C,
    db: Box<dyn Database>,
    api: Box<dyn FederationApi>,
    secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

impl<CO> OwnedClientContext<CO> {
    pub fn borrow_with_module_config<'c, CB, F>(
        &'c self,
        to_cfg: F,
    ) -> BorrowedClientContext<'c, CB>
    where
        F: FnOnce(&'c CO) -> &'c CB,
    {
        BorrowedClientContext {
            config: to_cfg(&self.config),
            db: self.db.as_ref(),
            api: self.api.as_ref(),
            secp: &self.secp,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAndGatewayConfig {
    pub client: ClientConfig,
    pub gateway: LightningGateway,
}

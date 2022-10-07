use std::collections::BTreeMap;

use fedimint_api::config::BitcoindRpcCfg;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct Guardian {
    name: String,
    connection_string: String,
}

/// Settings provided by the user when setting up the federation
#[derive(Debug)]
pub struct ConfigParams {
    pub federation_name: String,
    pub guardians: Vec<Guardian>,
    pub amount_tiers: Vec<fedimint_api::Amount>,
    pub btc_rpc: BitcoindRpcCfg,
    // an escape hatch for any settings we did not anticipate
    pub other: BTreeMap<String, serde_json::Value>,
}

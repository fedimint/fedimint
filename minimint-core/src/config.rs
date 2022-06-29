use minimint_ln::config::LightningModuleClientConfig;
use minimint_mint::config::MintClientConfig;
use minimint_wallet::config::WalletClientConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub api_endpoints: Vec<String>,
    pub mint: MintClientConfig,
    pub wallet: WalletClientConfig,
    pub ln: LightningModuleClientConfig,
    pub fee_consensus: FeeConsensus,
    pub max_evil: usize,
}

// TODO: get rid of it here, modules should govern their oen fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub fee_coin_spend_abs: minimint_api::Amount,
    pub fee_peg_in_abs: minimint_api::Amount,
    pub fee_coin_issuance_abs: minimint_api::Amount,
    pub fee_peg_out_abs: minimint_api::Amount,
    pub fee_contract_input: minimint_api::Amount,
    pub fee_contract_output: minimint_api::Amount,
}

pub fn load_from_file<T: DeserializeOwned>(path: &Path) -> T {
    let file = std::fs::File::open(path).expect("Can't read cfg file.");
    serde_json::from_reader(file).expect("Could not parse cfg file.")
}

pub mod serde_binary_human_readable {
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(x: &T, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let bytes =
                bincode::serialize(x).map_err(|e| serde::ser::Error::custom(format!("{:?}", e)))?;
            s.serialize_str(&hex::encode(&bytes))
        } else {
            Serialize::serialize(x, s)
        }
    }

    pub fn deserialize<'d, T: DeserializeOwned, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
        if d.is_human_readable() {
            let bytes = hex::decode::<String>(Deserialize::deserialize(d)?)
                .map_err(serde::de::Error::custom)?;
            bincode::deserialize(&bytes).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
        } else {
            Deserialize::deserialize(d)
        }
    }
}

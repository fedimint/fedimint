use bitcoin_hashes::Hash as BitcoinHash;
use fedimint_api::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

use crate::contracts::{ContractId, IdentifyableContract};

/// A generic contract to hold money in a pub key locked account
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct AccountContract {
    pub key: secp256k1::XOnlyPublicKey,
}

impl IdentifyableContract for AccountContract {
    fn contract_id(&self) -> ContractId {
        let mut engine = ContractId::engine();
        Encodable::consensus_encode(self, &mut engine).expect("Hashing never fails");
        ContractId::from_engine(engine)
    }
}

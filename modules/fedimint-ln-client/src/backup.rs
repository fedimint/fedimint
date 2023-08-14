use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_ln_common::LightningGateway;
use serde::{Deserialize, Serialize};

/// Snapshot of lightning state
///
/// Used to speed up and improve privacy of lightning recovery,
/// by avoiding scanning the whole history.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Encodable, Decodable)]
pub struct LightningBackup {
    pub gateways: Vec<LightningGateway>,
    pub next_incoming_contract_index: u64,
    pub next_outgoing_contract_index: u64,
}

impl LightningBackup {
    pub fn new_empty() -> Self {
        Self {
            gateways: vec![],
            next_incoming_contract_index: 0,
            next_outgoing_contract_index: 0,
        }
    }
}

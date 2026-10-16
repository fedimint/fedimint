use super::{
    Bolt11Invoice, Deserialize, LightningOperationMetaPay, OperationId, OutPoint, Serialize,
    secp256k1,
};
use crate::recurring::ReurringPaymentReceiveMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightningOperationMetaVariant {
    Pay(LightningOperationMetaPay),
    Receive {
        out_point: OutPoint,
        invoice: Bolt11Invoice,
        gateway_id: Option<secp256k1::PublicKey>,
    },
    ReceiveReclaim {
        original_operation_id: OperationId,
        invoice: Bolt11Invoice,
        gateway_id: Option<secp256k1::PublicKey>,
    },
    #[deprecated(
        since = "0.7.0",
        note = "Use recurring payment functionality instead instead"
    )]
    Claim {
        out_points: Vec<OutPoint>,
    },
    RecurringPaymentReceive(ReurringPaymentReceiveMeta),
}

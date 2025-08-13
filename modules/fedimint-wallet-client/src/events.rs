use bitcoin::Txid;
use fedimint_core::Amount;
use fedimint_core::core::ModuleKind;
use fedimint_eventlog::{Event, EventKind, EventPersistence};
use serde::{Deserialize, Serialize};

/// Event that is emitted when the client pegs-out ecash onchain
#[derive(Serialize, Deserialize)]
pub struct WithdrawRequest {
    /// The bitcoin transaction ID
    pub txid: Txid,
}

impl Event for WithdrawRequest {
    const MODULE: Option<ModuleKind> = Some(fedimint_wallet_common::KIND);

    const KIND: EventKind = EventKind::from_static("withdraw-request");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

/// Event that is emitted when the client confirms an onchain deposit.
#[derive(Serialize, Deserialize)]
pub struct DepositConfirmed {
    /// The bitcoin transaction ID
    pub txid: Txid,

    /// The out index of the deposit transaction
    pub out_idx: u32,

    /// The amount being deposited
    pub amount: Amount,
}

impl Event for DepositConfirmed {
    const MODULE: Option<ModuleKind> = Some(fedimint_wallet_common::KIND);
    const KIND: EventKind = EventKind::from_static("deposit-confirmed");
    const PERSISTENCE: EventPersistence = EventPersistence::Persistent;
}

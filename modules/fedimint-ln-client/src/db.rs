use std::time::SystemTime;

use bitcoin_hashes::sha256;
use fedimint_client::sm::DynState;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_ln_common::LightningGatewayRegistration;
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::pay::{
    LightningPayCommon, LightningPayRefund, LightningPayRefundV0, LightningPayStateMachine,
    LightningPayStates,
};
use crate::receive::{
    LightningReceiveStateMachine, LightningReceiveStates, LightningReceiveSubmittedOffer,
    LightningReceiveSubmittedOfferV0,
};
use crate::{LightningClientStateMachines, OutgoingLightningPayment, ReceivingKey};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    // Deprecated
    ActiveGateway = 0x28,
    PaymentResult = 0x29,
    MetaOverrides = 0x30,
    LightningGateway = 0x45,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ActiveGatewayKey;

#[derive(Debug, Encodable, Decodable)]
pub struct ActiveGatewayKeyPrefix;

impl_db_record!(
    key = ActiveGatewayKey,
    value = LightningGatewayRegistration,
    db_prefix = DbKeyPrefix::ActiveGateway,
);
impl_db_lookup!(
    key = ActiveGatewayKey,
    query_prefix = ActiveGatewayKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResultKey {
    pub payment_hash: sha256::Hash,
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResultPrefix;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct PaymentResult {
    pub index: u16,
    pub completed_payment: Option<OutgoingLightningPayment>,
}

impl_db_record!(
    key = PaymentResultKey,
    value = PaymentResult,
    db_prefix = DbKeyPrefix::PaymentResult,
);

impl_db_lookup!(key = PaymentResultKey, query_prefix = PaymentResultPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverridesKey;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverridesPrefix;

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaOverrides {
    pub value: String,
    pub fetched_at: SystemTime,
}

impl_db_record!(
    key = MetaOverridesKey,
    value = MetaOverrides,
    db_prefix = DbKeyPrefix::MetaOverrides,
);

impl_db_lookup!(key = MetaOverridesKey, query_prefix = MetaOverridesPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGatewayRegistration,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

pub(crate) fn get_v1_migrated_state(
    bytes: &[u8],
    module_instance_id: ModuleInstanceId,
    decoders: &ModuleDecoderRegistry,
) -> anyhow::Result<Option<DynState>> {
    let mut cursor = std::io::Cursor::new(bytes);
    let key = fedimint_core::core::ModuleInstanceId::consensus_decode(&mut cursor, decoders)?;
    debug_assert_eq!(key, module_instance_id, "Unexpected module instance ID");

    let ln_sm_variant = u16::consensus_decode(&mut cursor, decoders)?;

    // If the state machine is not a receive state machine, return None
    if ln_sm_variant != 2 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode(&mut cursor, decoders)?;
    let operation_id = OperationId::consensus_decode(&mut cursor, decoders)?;
    let receive_sm_variant = u16::consensus_decode(&mut cursor, decoders)?;

    // If the receive state machine is not a SubmittedOffer variant, return None
    if receive_sm_variant != 0 {
        return Ok(None);
    }

    let _receive_sm_len = u16::consensus_decode(&mut cursor, decoders)?;

    let v0 = LightningReceiveSubmittedOfferV0::consensus_decode(&mut cursor, decoders)?;

    let new_offer = LightningReceiveSubmittedOffer {
        offer_txid: v0.offer_txid,
        invoice: v0.invoice,
        receiving_key: ReceivingKey::Personal(v0.payment_keypair),
    };
    let new_recv = LightningReceiveStateMachine {
        operation_id,
        state: LightningReceiveStates::SubmittedOffer(new_offer),
    };
    let new = LightningClientStateMachines::Receive(new_recv);

    Ok(Some(new.into_dyn(module_instance_id)))
}

pub(crate) fn get_v2_migrated_state(
    bytes: &[u8],
    module_instance_id: ModuleInstanceId,
    decoders: &ModuleDecoderRegistry,
) -> anyhow::Result<Option<DynState>> {
    let mut cursor = std::io::Cursor::new(bytes);
    let key = ModuleInstanceId::consensus_decode(&mut cursor, decoders)?;
    debug_assert_eq!(key, module_instance_id, "Unexpected module instance ID");

    let ln_sm_variant = u16::consensus_decode(&mut cursor, decoders)?;

    // If the state machine is not a pay state machine, return None
    if ln_sm_variant != 1 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode(&mut cursor, decoders)?;
    let common = LightningPayCommon::consensus_decode(&mut cursor, decoders)?;
    let pay_sm_variant = u16::consensus_decode(&mut cursor, decoders)?;

    // if the pay state machine is not `refund` variant, return none
    if pay_sm_variant != 5 {
        return Ok(None);
    }

    let _pay_sm_len = u16::consensus_decode(&mut cursor, decoders)?;
    let v0 = LightningPayRefundV0::consensus_decode(&mut cursor, decoders)?;
    let v1 = LightningPayRefund {
        txid: v0.txid,
        out_points: v0.out_points,
        error_reason: "unknown error (database migration)".to_string(),
    };
    let new_pay = LightningPayStateMachine {
        common,
        state: LightningPayStates::Refund(v1),
    };
    let new_sm = LightningClientStateMachines::LightningPay(new_pay);
    Ok(Some(new_sm.into_dyn(module_instance_id)))
}

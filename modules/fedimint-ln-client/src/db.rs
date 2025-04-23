use std::io::Cursor;

use bitcoin::hashes::sha256;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::{OutPoint, TransactionId, impl_db_lookup, impl_db_record};
use fedimint_ln_common::{LightningGateway, LightningGatewayRegistration};
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::pay::lightningpay::LightningPayStates;
use crate::pay::{
    LightningPayCommon, LightningPayFunded, LightningPayRefund, LightningPayStateMachine,
    PayInvoicePayload,
};
use crate::receive::{
    LightningReceiveConfirmedInvoice, LightningReceiveStateMachine, LightningReceiveStates,
    LightningReceiveSubmittedOffer, LightningReceiveSubmittedOfferV0,
};
use crate::recurring::RecurringPaymentCodeEntry;
use crate::{LightningClientStateMachines, OutgoingLightningPayment, ReceivingKey};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    // Deprecated
    ActiveGateway = 0x28,
    PaymentResult = 0x29,
    MetaOverridesDeprecated = 0x30,
    LightningGateway = 0x45,
    RecurringPaymentKey = 0x46,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    CoreInternalReservedEnd = 0xff,
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

/// A single recurring payment code (e.g. LNURL) that was registered with a
/// server
#[derive(Debug, Encodable, Decodable)]
pub struct RecurringPaymentCodeKey {
    pub derivation_idx: u64,
}

#[derive(Debug, Encodable, Decodable)]
pub struct RecurringPaymentCodeKeyPrefix;

impl_db_record!(
    key = RecurringPaymentCodeKey,
    value = RecurringPaymentCodeEntry,
    db_prefix = DbKeyPrefix::RecurringPaymentKey,
);

impl_db_lookup!(
    key = RecurringPaymentCodeKey,
    query_prefix = RecurringPaymentCodeKeyPrefix
);

/// Migrates `SubmittedOfferV0` to `SubmittedOffer` and `ConfirmedInvoiceV0` to
/// `ConfirmedInvoice`
pub(crate) fn get_v1_migrated_state(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    #[derive(Debug, Clone, Decodable)]
    pub struct LightningReceiveConfirmedInvoiceV0 {
        invoice: Bolt11Invoice,
        receiving_key: Keypair,
    }

    let decoders = ModuleDecoderRegistry::default();
    let ln_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    // If the state machine is not a receive state machine, return None
    if ln_sm_variant != 2 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;
    let _operation_id = OperationId::consensus_decode_partial(cursor, &decoders)?;
    let receive_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    let new = match receive_sm_variant {
        // SubmittedOfferV0
        0 => {
            let _receive_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;

            let v0 = LightningReceiveSubmittedOfferV0::consensus_decode_partial(cursor, &decoders)?;

            let new_offer = LightningReceiveSubmittedOffer {
                offer_txid: v0.offer_txid,
                invoice: v0.invoice,
                receiving_key: ReceivingKey::Personal(v0.payment_keypair),
            };
            let new_recv = LightningReceiveStateMachine {
                operation_id,
                state: LightningReceiveStates::SubmittedOffer(new_offer),
            };
            LightningClientStateMachines::Receive(new_recv)
        }
        // ConfirmedInvoiceV0
        2 => {
            let _receive_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;
            let confirmed_old =
                LightningReceiveConfirmedInvoiceV0::consensus_decode_partial(cursor, &decoders)?;
            let confirmed_new = LightningReceiveConfirmedInvoice {
                invoice: confirmed_old.invoice,
                receiving_key: ReceivingKey::Personal(confirmed_old.receiving_key),
            };
            LightningClientStateMachines::Receive(LightningReceiveStateMachine {
                operation_id,
                state: LightningReceiveStates::ConfirmedInvoice(confirmed_new),
            })
        }
        _ => return Ok(None),
    };

    let bytes = new.consensus_encode_to_vec();
    Ok(Some((bytes, operation_id)))
}

/// Migrates `SubmittedOffer` with enum prefix 5 back to `SubmittedOffer`
pub(crate) fn get_v2_migrated_state(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();
    let ln_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    // If the state machine is not a receive state machine, return None
    if ln_sm_variant != 2 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;
    let _operation_id = OperationId::consensus_decode_partial(cursor, &decoders)?;
    let receive_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;
    if receive_sm_variant != 5 {
        return Ok(None);
    }

    let _receive_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;
    let old = LightningReceiveSubmittedOffer::consensus_decode_partial(cursor, &decoders)?;

    let new_recv = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
        operation_id,
        state: LightningReceiveStates::SubmittedOffer(old),
    });

    let bytes = new_recv.consensus_encode_to_vec();
    Ok(Some((bytes, operation_id)))
}

/// Migrates `Refund` state with enum prefix 5 to contain the `error_reason`
/// field
pub(crate) fn get_v3_migrated_state(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();
    let ln_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    // If the state machine is not a pay state machine, return None
    if ln_sm_variant != 1 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;
    let common = LightningPayCommon::consensus_decode_partial(cursor, &decoders)?;
    let pay_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    let _pay_sm_len = u16::consensus_decode_partial(cursor, &decoders)?;

    // if the pay state machine is not `Refund` or `Funded` variant, return none
    match pay_sm_variant {
        // Funded
        2 => {
            #[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
            pub struct LightningPayFundedV0 {
                pub payload: PayInvoicePayload,
                pub gateway: LightningGateway,
                pub timelock: u32,
            }

            let v0 = LightningPayFundedV0::consensus_decode_partial(cursor, &decoders)?;
            let v1 = LightningPayFunded {
                payload: v0.payload,
                gateway: v0.gateway,
                timelock: v0.timelock,
                funding_time: fedimint_core::time::now(),
            };

            let new_pay = LightningPayStateMachine {
                common,
                state: LightningPayStates::Funded(v1),
            };
            let new_sm = LightningClientStateMachines::LightningPay(new_pay);
            let bytes = new_sm.consensus_encode_to_vec();
            Ok(Some((bytes, operation_id)))
        }
        // Refund
        5 => {
            #[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
            pub struct LightningPayRefundV0 {
                txid: TransactionId,
                out_points: Vec<OutPoint>,
            }

            let v0 = LightningPayRefundV0::consensus_decode_partial(cursor, &decoders)?;
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
            let bytes = new_sm.consensus_encode_to_vec();
            Ok(Some((bytes, operation_id)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests;

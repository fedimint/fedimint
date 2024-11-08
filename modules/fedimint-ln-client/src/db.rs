use std::io::Cursor;

use bitcoin::hashes::sha256;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, TransactionId};
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
use crate::{LightningClientStateMachines, OutgoingLightningPayment, ReceivingKey};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    // Deprecated
    ActiveGateway = 0x28,
    PaymentResult = 0x29,
    MetaOverridesDeprecated = 0x30,
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
    let ln_sm_variant = u16::consensus_decode(cursor, &decoders)?;

    // If the state machine is not a receive state machine, return None
    if ln_sm_variant != 2 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode(cursor, &decoders)?;
    let _operation_id = OperationId::consensus_decode(cursor, &decoders)?;
    let receive_sm_variant = u16::consensus_decode(cursor, &decoders)?;

    let new = match receive_sm_variant {
        // SubmittedOfferV0
        0 => {
            let _receive_sm_len = u16::consensus_decode(cursor, &decoders)?;

            let v0 = LightningReceiveSubmittedOfferV0::consensus_decode(cursor, &decoders)?;

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
            let _receive_sm_len = u16::consensus_decode(cursor, &decoders)?;
            let confirmed_old =
                LightningReceiveConfirmedInvoiceV0::consensus_decode(cursor, &decoders)?;
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
    let ln_sm_variant = u16::consensus_decode(cursor, &decoders)?;

    // If the state machine is not a receive state machine, return None
    if ln_sm_variant != 2 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode(cursor, &decoders)?;
    let _operation_id = OperationId::consensus_decode(cursor, &decoders)?;
    let receive_sm_variant = u16::consensus_decode(cursor, &decoders)?;
    if receive_sm_variant != 5 {
        return Ok(None);
    }

    let _receive_sm_len = u16::consensus_decode(cursor, &decoders)?;
    let old = LightningReceiveSubmittedOffer::consensus_decode(cursor, &decoders)?;

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
    let ln_sm_variant = u16::consensus_decode(cursor, &decoders)?;

    // If the state machine is not a pay state machine, return None
    if ln_sm_variant != 1 {
        return Ok(None);
    }

    let _ln_sm_len = u16::consensus_decode(cursor, &decoders)?;
    let common = LightningPayCommon::consensus_decode(cursor, &decoders)?;
    let pay_sm_variant = u16::consensus_decode(cursor, &decoders)?;

    let _pay_sm_len = u16::consensus_decode(cursor, &decoders)?;

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

            let v0 = LightningPayFundedV0::consensus_decode(cursor, &decoders)?;
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

            let v0 = LightningPayRefundV0::consensus_decode(cursor, &decoders)?;
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
mod tests {
    use std::str::FromStr;

    use fedimint_client::db::migrate_state;
    use fedimint_core::core::{IntoDynInstance, OperationId};
    use fedimint_core::encoding::Encodable;
    use fedimint_core::secp256k1::{Keypair, SECP256K1};
    use fedimint_core::{BitcoinHash, TransactionId};
    use lightning_invoice::Bolt11Invoice;
    use rand::thread_rng;

    use crate::db::{get_v1_migrated_state, get_v2_migrated_state};
    use crate::receive::{
        LightningReceiveConfirmedInvoice, LightningReceiveStateMachine, LightningReceiveStates,
        LightningReceiveSubmittedOffer,
    };
    use crate::{LightningClientStateMachines, ReceivingKey};

    #[tokio::test]
    async fn test_sm_migration_to_v2_submitted() {
        let instance_id = 0x42;

        let dummy_invoice = Bolt11Invoice::from_str("lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",).expect("Invalid invoice");
        let claim_key = Keypair::new(SECP256K1, &mut thread_rng());
        let operation_id = OperationId::new_random();
        let txid = TransactionId::from_byte_array([42; 32]);

        let submitted_offer_variant_old = {
            let mut submitted_offer_variant = Vec::<u8>::new();
            txid.consensus_encode(&mut submitted_offer_variant)
                .expect("TransactionId is encodable");
            dummy_invoice
                .consensus_encode(&mut submitted_offer_variant)
                .expect("Invoice is encodable");
            claim_key
                .consensus_encode(&mut submitted_offer_variant)
                .expect("Keypair is encodable");

            submitted_offer_variant
        };

        let receive_variant = {
            let mut receive_variant = Vec::<u8>::new();
            operation_id
                .consensus_encode(&mut receive_variant)
                .expect("OperationId is encodable");
            0u64.consensus_encode(&mut receive_variant)
                .expect("u64 is encodable"); // Submitted Invoice variant
            submitted_offer_variant_old
                .consensus_encode(&mut receive_variant)
                .expect("State is encodable");
            receive_variant
        };

        let old_state = {
            let mut sm_bytes = Vec::<u8>::new();
            instance_id
                .consensus_encode(&mut sm_bytes)
                .expect("u16 is encodable");
            2u64.consensus_encode(&mut sm_bytes)
                .expect("u64 is encodable"); // Receive state machine variant
            receive_variant
                .consensus_encode(&mut sm_bytes)
                .expect("receive variant is encodable");
            sm_bytes
        };

        let old_states = vec![(old_state, operation_id)];

        let new_state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id,
            state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                offer_txid: txid,
                invoice: dummy_invoice,
                receiving_key: ReceivingKey::Personal(claim_key),
            }),
        })
        .into_dyn(instance_id);

        let (new_active_states, new_inactive_states) =
            migrate_state(old_states.clone(), old_states, get_v1_migrated_state)
                .expect("Migration failed")
                .expect("Migration produced output");

        assert_eq!(new_inactive_states.len(), 1);
        assert_eq!(
            new_inactive_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );

        assert_eq!(new_active_states.len(), 1);
        assert_eq!(
            new_active_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );
    }

    #[tokio::test]
    async fn test_sm_migration_to_v2_confirmed() -> anyhow::Result<()> {
        let operation_id = OperationId::new_random();
        let instance_id = 0x42;
        let claim_key = Keypair::new(SECP256K1, &mut thread_rng());
        let dummy_invoice = Bolt11Invoice::from_str("lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",).expect("Invalid invoice");

        let confirmed_variant = {
            let mut confirmed_variant = Vec::<u8>::new();
            dummy_invoice.consensus_encode(&mut confirmed_variant)?;
            claim_key.consensus_encode(&mut confirmed_variant)?;
            confirmed_variant
        };

        let receive_variant = {
            let mut receive_variant = Vec::<u8>::new();
            operation_id.consensus_encode(&mut receive_variant)?;
            2u64.consensus_encode(&mut receive_variant)?; // Enum variant confirmed invoice
            confirmed_variant.consensus_encode(&mut receive_variant)?;
            receive_variant
        };

        let old_sm_bytes = {
            let mut sm_bytes_old = Vec::<u8>::new();
            instance_id.consensus_encode(&mut sm_bytes_old)?;
            2u64.consensus_encode(&mut sm_bytes_old)?; // Enum variant Receive
            receive_variant.consensus_encode(&mut sm_bytes_old)?;
            sm_bytes_old
        };

        let old_states = vec![(old_sm_bytes, operation_id)];

        let new_state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id,
            state: LightningReceiveStates::ConfirmedInvoice(LightningReceiveConfirmedInvoice {
                invoice: dummy_invoice,
                receiving_key: ReceivingKey::Personal(claim_key),
            }),
        })
        .into_dyn(instance_id);

        let (new_active_states, new_inactive_states) =
            migrate_state(old_states.clone(), old_states, get_v1_migrated_state)
                .expect("Migration failed")
                .expect("Migration produced output");

        assert_eq!(new_inactive_states.len(), 1);
        assert_eq!(
            new_inactive_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );

        assert_eq!(new_active_states.len(), 1);
        assert_eq!(
            new_active_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sm_migration_to_v3_submitted() {
        let instance_id = 0x42;

        let dummy_invoice = Bolt11Invoice::from_str("lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",).expect("Invalid invoice");
        let claim_key = Keypair::new(SECP256K1, &mut thread_rng());
        let operation_id = OperationId::new_random();
        let txid = TransactionId::from_byte_array([42; 32]);

        let submitted_offer_variant_deleted = {
            let mut submitted_offer_variant = Vec::<u8>::new();
            txid.consensus_encode(&mut submitted_offer_variant)
                .expect("TransactionId is encodable");
            dummy_invoice
                .consensus_encode(&mut submitted_offer_variant)
                .expect("Invoice is encodable");
            ReceivingKey::Personal(claim_key)
                .consensus_encode(&mut submitted_offer_variant)
                .expect("Keypair is encodable");

            submitted_offer_variant
        };

        let receive_variant = {
            let mut receive_variant = Vec::<u8>::new();
            operation_id
                .consensus_encode(&mut receive_variant)
                .expect("OperationId is encodable");
            5u64.consensus_encode(&mut receive_variant)
                .expect("u64 is encodable"); // Deleted Submitted Invoice variant
            submitted_offer_variant_deleted
                .consensus_encode(&mut receive_variant)
                .expect("State is encodable");
            receive_variant
        };

        let old_state = {
            let mut sm_bytes = Vec::<u8>::new();
            instance_id
                .consensus_encode(&mut sm_bytes)
                .expect("u16 is encodable");
            2u64.consensus_encode(&mut sm_bytes)
                .expect("u64 is encodable"); // Receive state machine variant
            receive_variant
                .consensus_encode(&mut sm_bytes)
                .expect("receive variant is encodable");
            sm_bytes
        };

        let old_states = vec![(old_state, operation_id)];

        let new_state = LightningClientStateMachines::Receive(LightningReceiveStateMachine {
            operation_id,
            state: LightningReceiveStates::SubmittedOffer(LightningReceiveSubmittedOffer {
                offer_txid: txid,
                invoice: dummy_invoice,
                receiving_key: ReceivingKey::Personal(claim_key),
            }),
        })
        .into_dyn(instance_id);

        let (new_active_states, new_inactive_states) =
            migrate_state(old_states.clone(), old_states, get_v2_migrated_state)
                .expect("Migration failed")
                .expect("Migration produced output");

        assert_eq!(new_inactive_states.len(), 1);
        assert_eq!(
            new_inactive_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );

        assert_eq!(new_active_states.len(), 1);
        assert_eq!(
            new_active_states[0],
            (new_state.consensus_encode_to_vec(), operation_id)
        );
    }
}

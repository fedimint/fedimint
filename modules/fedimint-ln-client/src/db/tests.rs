use std::str::FromStr;

use fedimint_client_module::db::migrate_state;
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

    let dummy_invoice = Bolt11Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .expect("Invalid invoice");
    let claim_key = Keypair::new(SECP256K1, &mut thread_rng());
    let operation_id = OperationId::new_random();
    let txid = TransactionId::from_byte_array([42; 32]);

    let submitted_offer_variant_old: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut txid.consensus_encode_to_vec());
        bytes.append(&mut dummy_invoice.consensus_encode_to_vec());
        bytes.append(&mut claim_key.consensus_encode_to_vec());
        bytes
    };

    let receive_variant: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut operation_id.consensus_encode_to_vec());
        bytes.append(&mut 0u64.consensus_encode_to_vec()); // Submitted Invoice variant.
        bytes.append(&mut submitted_offer_variant_old.consensus_encode_to_vec());
        bytes
    };

    let old_state: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut instance_id.consensus_encode_to_vec());
        bytes.append(&mut 2u64.consensus_encode_to_vec()); // Receive state machine variant.
        bytes.append(&mut receive_variant.consensus_encode_to_vec());
        bytes
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
    let dummy_invoice = Bolt11Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .expect("Invalid invoice");

    let confirmed_variant: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut dummy_invoice.consensus_encode_to_vec());
        bytes.append(&mut claim_key.consensus_encode_to_vec());
        bytes
    };

    let receive_variant: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut operation_id.consensus_encode_to_vec());
        bytes.append(&mut 2u64.consensus_encode_to_vec()); // Enum variant confirmed invoice.
        bytes.append(&mut confirmed_variant.consensus_encode_to_vec());
        bytes
    };

    let old_sm_bytes: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut instance_id.consensus_encode_to_vec());
        bytes.append(&mut 2u64.consensus_encode_to_vec()); // Enum variant Receive.
        bytes.append(&mut receive_variant.consensus_encode_to_vec());
        bytes
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

    let dummy_invoice = Bolt11Invoice::from_str(
        "lntbs1u1pj8308gsp5xhxz908q5usddjjm6mfq6nwc2nu62twwm6za69d32kyx8h49a4hqpp5j5egfqw9kf5e96nk\
        6htr76a8kggl0xyz3pzgemv887pya4flguzsdp5235xzmntwvsxvmmjypex2en4dejxjmn8yp6xsefqvesh2cm9wsss\
        cqp2rzjq0ag45qspt2vd47jvj3t5nya5vsn0hlhf5wel8h779npsrspm6eeuqtjuuqqqqgqqyqqqqqqqqqqqqqqqc9q\
        yysgqddrv0jqhyf3q6z75rt7nrwx0crxme87s8rx2rt8xr9slzu0p3xg3f3f0zmqavtmsnqaj5v0y5mdzszah7thrmg\
        2we42dvjggjkf44egqheymyw",
    )
    .expect("Invalid invoice");
    let claim_key = Keypair::new(SECP256K1, &mut thread_rng());
    let operation_id = OperationId::new_random();
    let txid = TransactionId::from_byte_array([42; 32]);

    let submitted_offer_variant_deleted: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut txid.consensus_encode_to_vec());
        bytes.append(&mut dummy_invoice.consensus_encode_to_vec());
        bytes.append(&mut ReceivingKey::Personal(claim_key).consensus_encode_to_vec());
        bytes
    };

    let receive_variant: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut operation_id.consensus_encode_to_vec());
        bytes.append(&mut 5u64.consensus_encode_to_vec()); // Deleted Submitted Invoice variant.
        bytes.append(&mut submitted_offer_variant_deleted.consensus_encode_to_vec());
        bytes
    };

    let old_state: Vec<u8> = {
        let mut bytes = Vec::new();
        bytes.append(&mut instance_id.consensus_encode_to_vec());
        bytes.append(&mut 2u64.consensus_encode_to_vec()); // Receive state machine variant.
        bytes.append(&mut receive_variant.consensus_encode_to_vec());
        bytes
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

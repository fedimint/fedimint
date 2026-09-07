use std::time::SystemTime;

use bitcoin::hashes::Hash as _;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_ln_common::LightningGateway;
use fedimint_ln_common::contracts::IdentifiableContract as _;
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret, RoutingFees};

use super::{
    GatewayPayError, LightningPayCommon, LightningPayCreatedOutgoingLnContract,
    LightningPayFederationUnreachable, LightningPayFederationUnreachableRefundFailed,
    LightningPayFederationUnreachableRefundSubmitted, LightningPayFunded, LightningPayRefund,
    LightningPayRefundable, LightningPayStateMachine, LightningPayStates, PayInvoicePayload,
    PaymentData,
};

#[test]
fn federation_unreachable_states_round_trip_after_restart() {
    let gateway_error = GatewayPayError::FederationUnreachable;
    let terminal = LightningPayStates::FederationUnreachable(LightningPayFederationUnreachable {
        txid: TransactionId::all_zeros(),
        out_points: vec![OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        }],
    });
    let submitted = LightningPayStates::FederationUnreachableRefundSubmitted(
        LightningPayFederationUnreachableRefundSubmitted {
            txid: TransactionId::all_zeros(),
            out_points: vec![],
        },
    );
    let decoders = ModuleDecoderRegistry::default();

    assert_eq!(
        GatewayPayError::consensus_decode_whole(
            &gateway_error.consensus_encode_to_vec(),
            &decoders
        )
        .expect("gateway error decodes"),
        gateway_error
    );
    assert_eq!(
        LightningPayStates::consensus_decode_whole(&terminal.consensus_encode_to_vec(), &decoders)
            .expect("terminal state decodes"),
        terminal
    );
    assert_eq!(
        LightningPayStates::consensus_decode_whole(&submitted.consensus_encode_to_vec(), &decoders)
            .expect("submitted refund state decodes"),
        submitted
    );
}

#[test]
fn pre_change_gateway_error_variant_keeps_its_encoding() {
    let fixture = [1, 0];

    assert_eq!(
        GatewayPayError::OutgoingContractError.consensus_encode_to_vec(),
        fixture
    );
    assert_eq!(
        GatewayPayError::consensus_decode_whole(&fixture, &ModuleDecoderRegistry::default())
            .expect("pre-change gateway error decodes"),
        GatewayPayError::OutgoingContractError
    );
}

#[test]
fn pre_change_client_state_variant_keeps_its_encoding() {
    let fixture = [1, 0];

    assert_eq!(
        LightningPayStates::FundingRejected.consensus_encode_to_vec(),
        fixture
    );
    assert_eq!(
        LightningPayStates::consensus_decode_whole(&fixture, &ModuleDecoderRegistry::default())
            .expect("pre-change client state decodes"),
        LightningPayStates::FundingRejected
    );
}

fn assert_variant_discriminant(value: &LightningPayStates, expected: u8) {
    assert_eq!(
        value.consensus_encode_to_vec()[0],
        expected,
        "persisted state discriminant changed"
    );
}

#[test]
#[allow(deprecated)]
fn every_client_state_discriminant_is_stable() {
    let common = test_common();
    let key = common.contract.recovery_key.public_key();
    let gateway = LightningGateway {
        federation_index: 0,
        gateway_redeem_key: key,
        node_pub_key: key,
        lightning_alias: String::new(),
        api: SafeUrl::parse("http://example.com").expect("valid test URL"),
        route_hints: vec![],
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        gateway_id: key,
        supports_private_payments: false,
    };
    let contract_id = common.contract.contract_account.contract.contract_id();
    let payload = PayInvoicePayload {
        federation_id: common.federation_id,
        contract_id,
        payment_data: PaymentData::Invoice(common.invoice.clone()),
        preimage_auth: common.preimage_auth,
    };
    let refundable = LightningPayRefundable {
        contract_id,
        block_timelock: 0,
        error: GatewayPayError::FederationUnreachable,
    };
    let states = [
        LightningPayStates::CreatedOutgoingLnContract(LightningPayCreatedOutgoingLnContract {
            funding_txid: TransactionId::all_zeros(),
            contract_id,
            gateway: gateway.clone(),
        }),
        LightningPayStates::FundingRejected,
        LightningPayStates::Funded(LightningPayFunded {
            payload,
            gateway,
            timelock: 0,
            funding_time: SystemTime::UNIX_EPOCH,
        }),
        LightningPayStates::Success(String::new()),
        LightningPayStates::Refundable(refundable.clone()),
        LightningPayStates::Refund(LightningPayRefund {
            txid: TransactionId::all_zeros(),
            out_points: vec![],
            error_reason: String::new(),
        }),
        LightningPayStates::Refunded(vec![]),
        LightningPayStates::Failure(String::new()),
        LightningPayStates::FederationUnreachablePendingRefund(refundable),
        LightningPayStates::FederationUnreachableRefundSubmitted(
            LightningPayFederationUnreachableRefundSubmitted {
                txid: TransactionId::all_zeros(),
                out_points: vec![],
            },
        ),
        LightningPayStates::FederationUnreachable(LightningPayFederationUnreachable {
            txid: TransactionId::all_zeros(),
            out_points: vec![],
        }),
        LightningPayStates::FederationUnreachableRefundFailed(
            LightningPayFederationUnreachableRefundFailed {
                txid: TransactionId::all_zeros(),
                out_points: vec![],
                error: String::new(),
            },
        ),
    ];

    for (expected, state) in states.iter().enumerate() {
        assert_variant_discriminant(state, expected as u8);
    }
    assert_eq!(
        states[8..]
            .iter()
            .map(Encodable::consensus_encode_to_vec)
            .collect::<Vec<_>>(),
        vec![
            vec![
                8, 35, 123, 90, 96, 101, 222, 25, 169, 91, 57, 92, 206, 92, 67, 171, 186, 253, 101,
                251, 38, 212, 48, 207, 150, 202, 57, 11, 203, 190, 94, 78, 228, 11, 0, 2, 0,
            ],
            [vec![9, 33], vec![0; 33],].concat(),
            [vec![10, 33], vec![0; 33],].concat(),
            [vec![11, 34], vec![0; 34],].concat(),
        ],
        "new persisted refund state encodings changed"
    );
}

fn test_common() -> LightningPayCommon {
    use bitcoin::hashes::{Hash as _, sha256};
    use fedimint_core::secp256k1::{Keypair, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[2; 32]).expect("valid secret");
    let recovery_key = Keypair::from_secret_key(&secp, &secret);
    let public_key = recovery_key.public_key();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(1000)
        .build_signed(|message| secp.sign_ecdsa_recoverable(message, &secret))
        .expect("test invoice");

    LightningPayCommon {
        operation_id: OperationId([0; 32]),
        federation_id: FederationId::dummy(),
        contract: OutgoingContractData {
            recovery_key,
            contract_account: OutgoingContractAccount {
                amount: Amount::from_msats(1000),
                contract: OutgoingContract {
                    hash: sha256::Hash::hash(&[0; 32]),
                    gateway_key: public_key,
                    timelock: 100,
                    user_key: public_key,
                    cancelled: false,
                },
            },
        },
        gateway_fee: Amount::ZERO,
        preimage_auth: sha256::Hash::hash(&[1; 32]),
        invoice,
    }
}

mod executor;

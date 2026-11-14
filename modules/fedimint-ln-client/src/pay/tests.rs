use std::sync::Arc;

use bitcoin::hashes::{Hash, sha256};
use fedimint_api_client::api::ServerError;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, OperationId};
use fedimint_core::secp256k1::{Keypair, SECP256K1, Secp256k1, SecretKey};
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, apply, async_trait_maybe_send};
use fedimint_ln_common::LightningGateway;
use fedimint_ln_common::contracts::IdentifiableContract;
use fedimint_ln_common::contracts::outgoing::{
    OutgoingContract, OutgoingContractAccount, OutgoingContractData,
};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret, RoutingFees};

use super::{
    Duration, GatewayPayError, LightningPayCommon, LightningPayFunded, PayInvoicePayload,
    PaymentData,
};
use crate::{GatewayConnection, LightningClientContext};

/// A gateway that has already paid the invoice, so every request for the
/// contract returns the preimage.
#[derive(Debug)]
struct PaidGatewayConnection {
    preimage: [u8; 32],
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for PaidGatewayConnection {
    async fn verify_gateway_availability(
        &self,
        _gateway: &LightningGateway,
    ) -> Result<(), ServerError> {
        Ok(())
    }

    async fn pay_invoice(
        &self,
        _gateway: LightningGateway,
        _payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        Ok(fedimint_core::hex::encode(self.preimage))
    }
}

/// A client that restarts more than three minutes after funding the outgoing
/// contract must still ask the gateway for the preimage. Before the fix, the
/// gateway transition of such a `Funded` state never resolved, so the payment
/// could only end in a refund even when the gateway had paid.
#[tokio::test]
async fn funded_state_resumed_long_after_funding_still_gets_preimage() {
    let preimage = [1; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let user_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let gateway_key = Keypair::new(SECP256K1, &mut rand::thread_rng());
    let timelock = 1_000;
    let federation_id = FederationId::dummy();

    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(payment_hash)
        .duration_since_epoch(fedimint_core::time::duration_since_epoch())
        .min_final_cltv_expiry_delta(0)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(1_000_000)
        .build_signed(|m| {
            Secp256k1::new().sign_ecdsa_recoverable(m, &SecretKey::new(&mut rand::thread_rng()))
        })
        .expect("invoice should build");

    let contract = OutgoingContract {
        hash: payment_hash,
        gateway_key: gateway_key.public_key(),
        timelock,
        user_key: user_key.public_key(),
        cancelled: false,
    };
    let common = LightningPayCommon {
        operation_id: OperationId::new_random(),
        federation_id,
        contract: OutgoingContractData {
            recovery_key: user_key,
            contract_account: OutgoingContractAccount {
                amount: Amount::from_sats(1_000),
                contract: contract.clone(),
            },
        },
        gateway_fee: Amount::ZERO,
        preimage_auth: sha256::Hash::hash(&[2; 32]),
        invoice: invoice.clone(),
    };
    let payload = PayInvoicePayload {
        federation_id,
        contract_id: contract.contract_id(),
        payment_data: PaymentData::Invoice(invoice),
        preimage_auth: common.preimage_auth,
    };
    let gateway = LightningGateway {
        federation_index: 0,
        gateway_redeem_key: gateway_key.public_key(),
        node_pub_key: gateway_key.public_key(),
        lightning_alias: "gateway".to_string(),
        api: SafeUrl::parse("http://127.0.0.1:8175/v1").expect("valid url"),
        route_hints: vec![],
        fees: RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        },
        gateway_id: gateway_key.public_key(),
        supports_private_payments: false,
    };

    // The client funded the contract an hour ago and has just restarted.
    let state = LightningPayFunded {
        payload,
        gateway,
        timelock,
        funding_time: fedimint_core::time::now() - Duration::from_hours(1),
    };
    let context = LightningClientContext {
        ln_decoder: Decoder::default(),
        redeem_key: user_key,
        gateway_conn: Arc::new(PaidGatewayConnection { preimage }),
        client_ctx: None,
    };

    // The first transition asks the gateway for the preimage. The others wait
    // for a contract cancellation or timeout and are not polled here.
    let gateway_transition = state
        .transitions(common, context, DynGlobalClientContext::from(()))
        .into_iter()
        .next()
        .expect("Funded state has a gateway transition");
    let output = tokio::time::timeout(Duration::from_secs(10), gateway_transition.trigger)
        .await
        .expect("the gateway transition should resolve after a restart");
    let result: Result<String, GatewayPayError> =
        serde_json::from_value(output).expect("trigger output should decode");

    assert_eq!(result, Ok(fedimint_core::hex::encode(preimage)));
}

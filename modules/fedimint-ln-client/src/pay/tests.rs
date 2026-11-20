use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

const PREIMAGE: [u8; 32] = [1; 32];

/// A gateway that answers its first requests with the given errors and then
/// returns the preimage, as a gateway that has paid the invoice does. It counts
/// the requests it receives.
#[derive(Debug)]
struct ScriptedGatewayConnection {
    errors_before_preimage: Vec<GatewayPayError>,
    requests: AtomicUsize,
}

impl ScriptedGatewayConnection {
    fn new(errors_before_preimage: Vec<GatewayPayError>) -> Arc<Self> {
        Arc::new(Self {
            errors_before_preimage,
            requests: AtomicUsize::new(0),
        })
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for ScriptedGatewayConnection {
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
        let request = self.requests.fetch_add(1, Ordering::SeqCst);
        match self.errors_before_preimage.get(request) {
            Some(err) => Err(err.clone()),
            None => Ok(fedimint_core::hex::encode(PREIMAGE)),
        }
    }
}

/// Runs the gateway transition of a `Funded` state whose contract was funded
/// `funded_ago` before now, against `gateway_conn`, and returns its result.
async fn run_gateway_transition(
    gateway_conn: Arc<ScriptedGatewayConnection>,
    funded_ago: Duration,
) -> Result<String, GatewayPayError> {
    let payment_hash = sha256::Hash::hash(&PREIMAGE);
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

    let state = LightningPayFunded {
        payload,
        gateway,
        timelock,
        funding_time: fedimint_core::time::now() - funded_ago,
    };
    let context = LightningClientContext {
        ln_decoder: Decoder::default(),
        redeem_key: user_key,
        gateway_conn,
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
        .expect("the gateway transition should resolve");
    serde_json::from_value(output).expect("trigger output should decode")
}

/// A client that restarts more than three minutes after funding the outgoing
/// contract must still ask the gateway for the preimage. Before the fix, the
/// gateway transition of such a `Funded` state never resolved, so the payment
/// could only end in a refund even when the gateway had paid.
#[tokio::test]
async fn funded_state_resumed_long_after_funding_still_gets_preimage() {
    let gateway = ScriptedGatewayConnection::new(vec![]);

    let result = run_gateway_transition(gateway.clone(), Duration::from_hours(1)).await;

    assert_eq!(result, Ok(fedimint_core::hex::encode(PREIMAGE)));
    assert_eq!(gateway.requests(), 1);
}

/// A gateway that cannot be reached is asked again after a backoff, and the
/// payment completes once the gateway returns the preimage.
#[tokio::test]
async fn unreachable_gateway_is_asked_again_until_it_returns_the_preimage() {
    let not_found = GatewayPayError::GatewayInternalError {
        error_code: Some(404),
        error_message: "gateway not found".to_string(),
    };
    let gateway = ScriptedGatewayConnection::new(vec![not_found.clone(), not_found]);

    let result = run_gateway_transition(gateway.clone(), Duration::ZERO).await;

    assert_eq!(result, Ok(fedimint_core::hex::encode(PREIMAGE)));
    assert_eq!(gateway.requests(), 3);
}

/// `OutgoingContractError` means the federation has no such contract, so
/// asking the gateway again cannot help and it is asked only once.
#[tokio::test]
async fn outgoing_contract_error_is_not_retried() {
    let gateway = ScriptedGatewayConnection::new(vec![GatewayPayError::OutgoingContractError; 3]);

    let result = run_gateway_transition(gateway.clone(), Duration::ZERO).await;

    assert_eq!(result, Err(GatewayPayError::OutgoingContractError));
    assert_eq!(gateway.requests(), 1);
}

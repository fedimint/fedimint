use std::time::Duration;

use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{All, KeyPair, Secp256k1};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_ln_common::bitcoin;
use fedimint_lnv2_client::api::GatewayConnection;
use fedimint_lnv2_client::{
    CreateBolt11InvoicePayload, GatewayError, LightningInvoice, PaymentFee, RoutingInfo,
};
use fedimint_lnv2_common::contracts::OutgoingContract;
use fedimint_testing::ln::{INVALID_INVOICE_PAYMENT_SECRET, MOCK_INVOICE_PREIMAGE};
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};

#[derive(Debug)]
pub struct MockGatewayConnection {
    ctx: Secp256k1<All>,
    keypair: KeyPair,
}

impl Default for MockGatewayConnection {
    fn default() -> Self {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let keypair = KeyPair::new_global(&mut OsRng);
        MockGatewayConnection { ctx, keypair }
    }
}

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for MockGatewayConnection {
    async fn fetch_routing_info(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: &FederationId,
    ) -> Result<Option<RoutingInfo>, GatewayError> {
        Ok(Some(RoutingInfo {
            public_key: self.keypair.public_key(),
            send_fee_default: PaymentFee::one_percent(),
            send_fee_minimum: PaymentFee::half_of_one_percent(),
            receive_fee: PaymentFee::half_of_one_percent(),
            expiration_delta_default: 500,
            expiration_delta_minimum: 144,
        }))
    }

    async fn fetch_invoice(
        &self,
        _gateway_api: SafeUrl,
        payload: CreateBolt11InvoicePayload,
    ) -> Result<Result<Bolt11Invoice, String>, GatewayError> {
        Ok(Ok(InvoiceBuilder::new(Currency::Regtest)
            .description(String::new())
            .payment_hash(payload.contract.commitment.payment_hash)
            .current_timestamp()
            .min_final_cltv_expiry_delta(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(payload.invoice_amount.msats)
            .expiry_time(Duration::from_secs(payload.expiry_time as u64))
            .build_signed(|m| {
                self.ctx
                    .sign_ecdsa_recoverable(m, &self.keypair.secret_key())
            })
            .unwrap()))
    }

    async fn try_gateway_send_payment(
        &self,
        _gateway_api: SafeUrl,
        _federation_id: FederationId,
        contract: OutgoingContract,
        invoice: LightningInvoice,
        _auth: Signature,
    ) -> anyhow::Result<Result<Result<[u8; 32], Signature>, String>> {
        match invoice {
            LightningInvoice::Bolt11(invoice, _) => {
                if *invoice.payment_secret() == PaymentSecret(INVALID_INVOICE_PAYMENT_SECRET) {
                    let signature = self.keypair.sign_schnorr(contract.forfeit_message());
                    return Ok(Ok(Err(signature)));
                }

                Ok(Ok(Ok(MOCK_INVOICE_PREIMAGE)))
            }
        }
    }
}

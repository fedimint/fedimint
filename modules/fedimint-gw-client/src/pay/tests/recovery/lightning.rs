use bitcoin::hashes::sha256;
use fedimint_client::ClientHandleArc;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::util::Spanned;
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError, PayInvoiceResponse};
use fedimint_ln_client::pay::PaymentData;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use lightning_invoice::RoutingFees;
use tokio::sync::watch;

use crate::IGatewayClientV1;
use crate::error::GatewayClientV1Error;
use crate::pay::OutgoingPaymentError;

/// A node with an already dispatched payment, independent of the client DB.
#[derive(Debug)]
pub(super) struct MockLightning {
    pub(super) settled: watch::Sender<bool>,
    pub(super) resumes: watch::Sender<usize>,
}

impl MockLightning {
    pub(super) fn new(settled: bool) -> Self {
        Self {
            settled: watch::channel(settled).0,
            resumes: watch::channel(0).0,
        }
    }
}

#[async_trait::async_trait]
impl IGatewayClientV1 for MockLightning {
    async fn verify_preimage_authentication(
        &self,
        _: sha256::Hash,
        _: sha256::Hash,
        _: OutgoingContractAccount,
    ) -> Result<(), OutgoingPaymentError> {
        Ok(())
    }
    async fn verify_pruned_invoice(&self, _: PaymentData) -> Result<(), GatewayClientV1Error> {
        unimplemented!()
    }
    async fn get_routing_fees(&self, _: FederationId) -> Option<RoutingFees> {
        Some(RoutingFees {
            base_msat: 0,
            proportional_millionths: 0,
        })
    }
    async fn begin_fresh_receive(
        &self,
        _: FederationId,
    ) -> Option<fedimint_gateway_common::PaymentPolicyGuard> {
        unimplemented!("recovery fixture must not admit fresh receives")
    }
    async fn get_client(&self, _: &FederationId) -> Option<Spanned<ClientHandleArc>> {
        unimplemented!()
    }
    async fn get_client_for_invoice(&self, _: PaymentData) -> Option<Spanned<ClientHandleArc>> {
        None
    }
    async fn pay(
        &self,
        payment_data: PaymentData,
        max_delay: u64,
        _: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        assert_eq!(
            payment_data,
            super::invoice().pay_invoice_payload.payment_data
        );
        assert_eq!(max_delay, 0, "expired budget must not allow fresh dispatch");
        self.resumes.send_modify(|calls| *calls += 1);
        self.settled
            .subscribe()
            .wait_for(|settled| *settled)
            .await
            .unwrap();
        Ok(PayInvoiceResponse {
            preimage: super::PREIMAGE,
        })
    }
    async fn outbound_payment_exists(&self, hash: sha256::Hash) -> bool {
        assert_eq!(
            hash,
            super::invoice()
                .pay_invoice_payload
                .payment_data
                .payment_hash()
        );
        true
    }
    async fn complete_htlc(&self, _: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        unimplemented!()
    }
    async fn is_lnv2_direct_swap(
        &self,
        _: sha256::Hash,
        _: Amount,
    ) -> Result<
        Option<(
            fedimint_lnv2_common::contracts::IncomingContract,
            ClientHandleArc,
        )>,
        GatewayClientV1Error,
    > {
        Ok(None)
    }
    async fn claim_payment_image(
        &self,
        _: &fedimint_lnv2_common::contracts::PaymentImage,
        _: OperationId,
    ) -> bool {
        unimplemented!()
    }
}

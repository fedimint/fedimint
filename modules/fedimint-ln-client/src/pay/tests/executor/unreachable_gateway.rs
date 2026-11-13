use fedimint_api_client::api::ServerError;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_ln_common::LightningGateway;

use crate::pay::PayInvoicePayload;
use crate::{GatewayConnection, GatewayPayError};

/// A reachable gateway that cannot reach the payout federation.
#[derive(Debug)]
pub(super) struct UnreachableGateway;

#[apply(async_trait_maybe_send!)]
impl GatewayConnection for UnreachableGateway {
    async fn verify_gateway_availability(&self, _: &LightningGateway) -> Result<(), ServerError> {
        Ok(())
    }

    async fn pay_invoice(
        &self,
        _: LightningGateway,
        payload: PayInvoicePayload,
    ) -> Result<String, GatewayPayError> {
        let common = super::test_common();
        assert_eq!(payload.federation_id, common.federation_id);
        assert_eq!(payload.preimage_auth, common.preimage_auth);
        Err(GatewayPayError::FederationUnreachable)
    }
}

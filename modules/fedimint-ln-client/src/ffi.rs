use std::str::FromStr;

use anyhow::anyhow;
use bitcoin::secp256k1::SecretKey;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::ffi::UniffiError;
use fedimint_core::{Amount, UnifiedCallback, UnifiedCallbackEvent, runtime};
use fedimint_ln_common::{LightningGateway, LightningGatewayAnnouncement};
use futures::StreamExt;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use serde::{Deserialize, Serialize};
use uniffi::custom_type;

use crate::{
    IDatabaseTransactionOpsCoreTyped, LightningClientModule, LightningGatewayKeyPrefix,
    OperationId, OutgoingLightningPayment, get_invoice,
};

uniffi::custom_type!(Bolt11Invoice, String, {
    remote,
    lower: |invoice| invoice.to_string(),
    try_lift: |s| Bolt11Invoice::from_str(&s).map_err(|e| anyhow!(e)),
});

uniffi::custom_type!(Bolt11InvoiceDescription, String, {
    remote,
    lower: |desc| desc.to_string(),
    try_lift: |s| Ok(Bolt11InvoiceDescription::Direct(
                    lightning_invoice::Description::new(s).map_err(|e| anyhow!(e))?)),
});

uniffi::custom_type!(PublicKey, String, {
    remote,
    lower: |pk| pk.to_string(),
    try_lift: |s| PublicKey::from_str(&s).map_err(|e| anyhow!(e)),
});

uniffi::custom_type!(SecretKey, String, {
    remote,
    lower: |sk| sk.display_secret().to_string(),
    try_lift: |s| SecretKey::from_str(&s).map_err(|e| anyhow!(e)),
});

type Result<T> = std::result::Result<T, UniffiError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bolt11InvoiceResponse {
    pub operation_id: OperationId,
    pub invoice: Bolt11Invoice,
    pub preimage: [u8; 32],
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CreateBolt11InvoiceResponse {
    pub operation_id: OperationId,
    pub invoice: Bolt11Invoice,
}

custom_type!(Bolt11InvoiceResponse, String, {
    lower: |r| serde_json::to_string(&r).expect("Bolt11InvoiceResponse always serializes"),
    try_lift: |s| serde_json::from_str(&s).map_err(|e| anyhow!(e)),
});

#[uniffi::export(async_runtime = "tokio")]
impl LightningClientModule {
    #[uniffi::method(name = "create_bolt11_invoice")]
    pub async fn create_bolt11_invoice_uniffi(
        &self,
        amount: Amount,
        description: Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        extra_meta: String,
        gateway: Option<LightningGateway>,
    ) -> Result<CreateBolt11InvoiceResponse> {
        let (operation_id, invoice, _) = self
            .create_bolt11_invoice(amount, description, expiry_time, extra_meta, gateway)
            .await?;
        Ok(CreateBolt11InvoiceResponse {
            operation_id,
            invoice,
        })
    }

    #[uniffi::method(name = "pay_bolt11_invoice")]
    pub async fn pay_bolt11_invoice_uniffi(
        &self,
        invoice: Bolt11Invoice,
        gateway: Option<LightningGateway>,
        extra_meta: Option<String>,
    ) -> Result<OutgoingLightningPayment> {
        let output = self
            .pay_bolt11_invoice(gateway, invoice, extra_meta)
            .await?;
        Ok(output)
    }

    #[uniffi::method(name = "subscribe_ln_pay")]
    pub async fn subscribe_ln_pay_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let ln = client_ctx.self_ref();
        let updates = ln.subscribe_ln_pay(operation_id).await?;
        runtime::spawn("uniffi-subscribe-ln-pay", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event("ln_pay", Some(operation_id), payload_json));
            }
        });
        Ok(())
    }

    #[uniffi::method(name = "subscribe_internal_pay")]
    pub async fn subscribe_internal_pay_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let ln = client_ctx.self_ref();
        let updates = ln.subscribe_internal_pay(operation_id).await?;
        runtime::spawn("uniffi-subscribe-internal-pay", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event(
                    "internal_pay",
                    Some(operation_id),
                    payload_json,
                ));
            }
        });
        Ok(())
    }

    #[uniffi::method(name = "subscribe_ln_receive")]
    pub async fn subscribe_ln_receive_uniffi(
        &self,
        operation_id: OperationId,
        callback: Box<dyn UnifiedCallback>,
    ) -> Result<()> {
        let client_ctx = self.client_ctx.clone();
        let ln = client_ctx.self_ref();
        let updates = ln.subscribe_ln_receive(operation_id).await?;
        runtime::spawn("uniffi-subscribe-ln-receive", async move {
            let mut stream = updates.into_stream();
            while let Some(state) = stream.next().await {
                let Ok(payload_json) = serde_json::to_string(&state) else {
                    continue;
                };
                callback.on_event(unified_event(
                    "ln_receive",
                    Some(operation_id),
                    payload_json,
                ));
            }
        });
        Ok(())
    }

    #[uniffi::method(name = "create_bolt11_invoice_for_user_tweaked")]
    pub async fn create_bolt11_invoice_for_user_tweaked_uniffi(
        &self,
        amount: Amount,
        description: lightning_invoice::Bolt11InvoiceDescription,
        expiry_time: Option<u64>,
        user_key: PublicKey,
        index: u64,
        extra_meta: String,
        gateway: Option<LightningGateway>,
    ) -> Result<CreateBolt11InvoiceResponse> {
        let client = self.client_ctx.self_ref();
        let (operation_id, invoice, _) = client
            .create_bolt11_invoice_for_user_tweaked(
                amount,
                description,
                expiry_time,
                user_key,
                index,
                extra_meta,
                gateway,
            )
            .await?;
        Ok(CreateBolt11InvoiceResponse {
            operation_id,
            invoice,
        })
    }

    #[uniffi::method(name = "update_gateway_cache")]
    pub async fn update_gateway_cache_uniffi(&self) -> Result<()> {
        self.update_gateway_cache().await?;
        Ok(())
    }

    #[uniffi::method(name = "list_gateways")]
    pub async fn list_gateways_uniffi(&self) -> Vec<LightningGatewayAnnouncement> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction_nc().await;
        dbtx.find_by_prefix(&LightningGatewayKeyPrefix)
            .await
            .map(|(_, gw)| gw.unanchor())
            .collect::<Vec<_>>()
            .await
    }

    #[uniffi::method(name = "select_available_gateway")]
    pub async fn select_available_gateway_uniffi(
        &self,
        maybe_gateway: Option<LightningGateway>,
        maybe_invoice: Option<Bolt11Invoice>,
    ) -> Result<Option<LightningGateway>> {
        Ok(self
            .select_available_gateway(maybe_gateway, maybe_invoice)
            .await
            .ok())
    }

    #[uniffi::method(name = "get_gateway")]
    pub async fn get_gateway_uniffi(
        &self,
        gateway_id: Option<PublicKey>,
        force_internal: bool,
    ) -> Result<Option<LightningGateway>> {
        Ok(self.get_gateway(gateway_id, force_internal).await?)
    }

    pub async fn pay_lightning_address(
        &self,
        lightning_address: String,
        amount: Amount,
    ) -> Result<OutgoingLightningPayment> {
        let invoice = get_invoice(&lightning_address, Some(amount), None).await?;
        let gateway = self.get_gateway(None, false).await?;
        Ok(self.pay_bolt11_invoice(gateway, invoice, ()).await?)
    }
}

fn unified_event(
    topic: &str,
    operation_id: Option<OperationId>,
    payload_json: String,
) -> UnifiedCallbackEvent {
    UnifiedCallbackEvent {
        source: "fedimint-ln-client".to_owned(),
        topic: topic.to_owned(),
        operation_id: operation_id.map(|id| id.fmt_full().to_string()),
        payload_json,
    }
}

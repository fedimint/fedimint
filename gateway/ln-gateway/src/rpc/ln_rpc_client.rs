use std::net::SocketAddr;

use bitcoin::XOnlyPublicKey;
use fedimint_server::modules::ln::contracts::Preimage;
use lightning_invoice::Invoice;
use secp256k1::PublicKey;
use tokio::sync::Mutex;
use tonic::{transport::Channel, Request, Streaming};

use crate::{
    gwlightningrpc::{
        gateway_lightning_client::GatewayLightningClient, GetPubKeyRequest, GetPubKeyResponse,
        PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
        SubscribeInterceptHtlcsResponse,
    },
    Result,
};

pub struct LnRpcClient {
    client: Mutex<GatewayLightningClient<Channel>>,
}

// Wrapper around `GatewayLightningClient`
// for convenience in constructing rpc requests and parsing responses.
impl LnRpcClient {
    pub async fn new(address: SocketAddr) -> Result<Self> {
        let url = format!("http://{}", address); // TODO: Support secure connections
        let client = GatewayLightningClient::connect(url)
            .await
            .expect("Failed to construct lightning rpc client");

        Ok(Self {
            client: Mutex::new(client),
        })
    }

    // Get the public key of the lightning node
    pub async fn get_pub_key(&self) -> Result<PublicKey> {
        let request = Request::new(GetPubKeyRequest {});
        let GetPubKeyResponse { pub_key } = self
            .client
            .lock()
            .await
            .get_pub_key(request)
            .await
            .expect("Failed to get pubkey")
            .into_inner();

        println!("NODE PUBKEY={:?}", pub_key);
        Ok(PublicKey::from_slice(&pub_key).expect("Failed to parse pubkey"))
    }

    // Attempt to pay an invoice using the lightning node
    pub async fn pay_invoice(
        &self,
        invoice: Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage> {
        let request = Request::new(PayInvoiceRequest {
            invoice: invoice.to_string(),
            max_delay,
            max_fee_percent,
        });
        let PayInvoiceResponse {
            payment_hash,
            preimage,
        } = self
            .client
            .lock()
            .await
            .pay_invoice(request)
            .await
            .expect("Failed to pay invoice")
            .into_inner();

        println!("PAYMENT HASH={:?}", payment_hash);
        let slice: [u8; 32] = preimage
            .to_vec()
            .try_into()
            .expect("Failed to parse preimage");
        Ok(Preimage(slice))
    }

    // Subscribe to intercept htlcs that belong to a specific mint
    pub async fn subscribe_intercept_htlcs(
        &self,
        mint_pub_key: XOnlyPublicKey,
    ) -> Result<Streaming<SubscribeInterceptHtlcsResponse>> {
        let request = Request::new(SubscribeInterceptHtlcsRequest {
            mint_pub_key: mint_pub_key.serialize().to_vec(),
        });
        let stream = self
            .client
            .lock()
            .await
            .subscribe_intercept_htlcs(request)
            .await
            .expect("Failed to subscribe intercept htlcs")
            .into_inner();

        println!("SUBSCRIBED TO INTERCEPT HTLCs...");
        Ok(stream)
    }
}

use std::{net::SocketAddr, ops::Sub, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{PublicKey, SecretKey},
    KeyPair, XOnlyPublicKey,
};
use fedimint_api::{task::TaskGroup, Amount};
use fedimint_server::modules::ln::contracts::Preimage;
use lightning::ln::PaymentSecret;
use lightning_invoice::{Currency, Invoice, InvoiceBuilder, DEFAULT_EXPIRY_TIME};
use ln_gateway::{
    rpc::{
        lnrpc_client::{ILnRpcClient, ILnRpcClientFactory, LnRpcClient},
        HtlcInterceptPayload,
    },
    Result,
};
use rand::rngs::OsRng;
use tokio::sync::{mpsc::Receiver, Mutex};

use super::LightningTest;

#[derive(Clone, Debug)]
pub struct FakeLightningTest {
    pub preimage: Preimage,
    node_pubkey: PublicKey,
    gateway_node_sec_key: SecretKey,
    amount_sent: Arc<Mutex<u64>>,
}

impl FakeLightningTest {
    pub fn new(_task_group: TaskGroup) -> Self {
        let ctx = bitcoin::secp256k1::Secp256k1::new();
        let kp = KeyPair::new(&ctx, &mut OsRng);
        let amount_sent = Arc::new(Mutex::new(0));

        FakeLightningTest {
            preimage: Preimage([1; 32]),
            gateway_node_sec_key: SecretKey::from_keypair(&kp),
            node_pubkey: PublicKey::from_keypair(&kp),
            amount_sent,
        }
    }
}

#[async_trait]
impl LightningTest for FakeLightningTest {
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let ctx = bitcoin::secp256k1::Secp256k1::new();

        InvoiceBuilder::new(Currency::Regtest)
            .description("".to_string())
            .payment_hash(sha256::Hash::hash(&self.preimage.0))
            .current_timestamp()
            .min_final_cltv_expiry(0)
            .payment_secret(PaymentSecret([0; 32]))
            .amount_milli_satoshis(amount.msats)
            .expiry_time(Duration::from_secs(
                expiry_time.unwrap_or(DEFAULT_EXPIRY_TIME),
            ))
            .build_signed(|m| ctx.sign_ecdsa_recoverable(m, &self.gateway_node_sec_key))
            .unwrap()
    }

    async fn amount_sent(&self) -> Amount {
        Amount::from_msats(*self.amount_sent.lock().await)
    }
}

#[async_trait]
impl ILnRpcClient for FakeLightningTest {
    async fn get_pubkey(&self) -> Result<PublicKey> {
        Ok(self.node_pubkey)
    }

    async fn pay_invoice(
        &self,
        invoice: lightning_invoice::Invoice,
        _max_delay: u64,
        _max_fee_percent: f64,
    ) -> Result<Preimage> {
        *self.amount_sent.lock().await += invoice.amount_milli_satoshis().unwrap();

        Ok(self.preimage.clone())
    }

    async fn subscribe_intercept_htlcs(
        &self,
        _mint_pub_key: XOnlyPublicKey,
    ) -> Result<Receiver<HtlcInterceptPayload>> {
        unimplemented!("subscribe intercept htlcs not implemented for test client")
    }
}

/**
 * An `ILnRpcClientFactory` that creates `FakeLightningTest` instances.
 */
#[derive(Debug, Default)]
pub struct FakeLnRpcClientFactory;

#[async_trait]
impl ILnRpcClientFactory for FakeLnRpcClientFactory {
    async fn create(&self, _address: SocketAddr, task_group: TaskGroup) -> Result<LnRpcClient> {
        let client = Arc::new(FakeLightningTest::new(task_group));
        Ok(LnRpcClient::new(client))
    }
}

pub struct RealLightningTest {
    rpc_gateway: Arc<Mutex<cln::ClnRpc>>,
    rpc_other: Arc<Mutex<cln::ClnRpc>>,
    initial_balance: Amount,
    pub node_pubkey: PublicKey,
}

impl RealLightningTest {
    pub async fn new(socket_gateway: PathBuf, socket_other: PathBuf) -> Self {
        let rpc_other = Arc::new(Mutex::new(cln::ClnRpc::new(socket_other).await.unwrap()));
        let rpc_gateway = Arc::new(Mutex::new(cln::ClnRpc::new(socket_gateway).await.unwrap()));

        let initial_balance = Self::channel_balance(rpc_gateway.clone()).await;

        let getinfo_resp = if let cln::Response::Getinfo(data) = rpc_gateway
            .lock()
            .await
            .call(cln::Request::Getinfo(
                cln::model::requests::GetinfoRequest {},
            ))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected GetinfoResponse")
        };

        let node_pubkey = PublicKey::from_str(&getinfo_resp.id.to_string()).unwrap();

        RealLightningTest {
            rpc_gateway,
            rpc_other,
            initial_balance,
            node_pubkey,
        }
    }

    async fn channel_balance(rpc: Arc<Mutex<cln::ClnRpc>>) -> Amount {
        let listfunds_req = cln::model::requests::ListfundsRequest { spent: Some(false) };
        let listfunds_resp = if let cln::Response::ListFunds(data) = rpc
            .lock()
            .await
            .call(cln::Request::ListFunds(listfunds_req))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected ListFundsResponse")
        };

        let funds: u64 = listfunds_resp
            .channels
            .iter()
            .filter(|channel| channel.short_channel_id.is_some() && channel.connected)
            .map(|channel| channel.our_amount_msat.msat())
            .sum();
        Amount::from_msats(funds)
    }
}

#[async_trait]
impl LightningTest for RealLightningTest {
    async fn invoice(&self, amount: Amount, expiry_time: Option<u64>) -> Invoice {
        let random: u64 = rand::random();
        let invoice_req = cln::model::requests::InvoiceRequest {
            amount_msat: cln::primitives::AmountOrAny::Amount(cln::primitives::Amount::from_msat(
                amount.msats,
            )),
            description: "".to_string(),
            label: random.to_string(),
            expiry: expiry_time,
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: None,
        };

        let invoice_resp = if let cln::Response::Invoice(data) = self
            .rpc_other
            .lock()
            .await
            .call(cln::Request::Invoice(invoice_req))
            .await
            .unwrap()
        {
            data
        } else {
            panic!("cln-rpc response did not match expected InvoiceResponse")
        };

        Invoice::from_str(&invoice_resp.bolt11).unwrap()
    }

    async fn amount_sent(&self) -> Amount {
        self.initial_balance
            .sub(Self::channel_balance(self.rpc_gateway.clone()).await)
    }
}

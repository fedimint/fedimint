use std::io::Cursor;

use anyhow::Error;
use bitcoin::{Address, Transaction};
use fedimint_api::{Amount, TransactionId};
use fedimint_server::{modules::ln::contracts::Preimage, modules::wallet::txoproof::TxOutProof};
use futures::Future;
use mint_client::{ln::PayInvoicePayload, FederationId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{mpsc, oneshot};

use crate::{cln::HtlcAccepted, Result};

#[derive(Debug, Clone)]
pub struct GatewayRpcSender {
    sender: mpsc::Sender<GatewayRequest>,
}

/// A two-way rpc channel for [`GatewayRequest`]s.
///
/// The channel consists of a long lived sender and receiver used to pass along the original message
/// And a short lived (oneshot tx, rx) is used to receive a response in the opposite direction as the original message.
impl GatewayRpcSender {
    pub fn new(sender: mpsc::Sender<GatewayRequest>) -> Self {
        Self { sender }
    }

    pub async fn send<R>(&self, message: R) -> std::result::Result<R::Response, Error>
    where
        R: GatewayRequestTrait,
    {
        let (sender, receiver) = oneshot::channel::<Result<R::Response>>();
        let msg = message.to_enum(sender);
        self.sender
            .send(msg)
            .await
            .expect("failed to send over channel");
        Ok(receiver.await.expect("Failed to send over channel")?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFedPayload {
    pub connect: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceivePaymentPayload {
    // NOTE: On ReceivePayment signal from ln_rpc,
    // we extract the relevant federation id from the accepted htlc
    pub htlc_accepted: HtlcAccepted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoPayload;

#[derive(Debug, Serialize, Deserialize)]
pub struct BalancePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositAddressPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositPayload {
    pub federation_id: FederationId,
    pub txout_proof: TxOutProof,
    #[serde(
        deserialize_with = "serde_hex_deserialize",
        serialize_with = "serde_hex_serialize"
    )]
    pub transaction: Transaction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawPayload {
    pub federation_id: FederationId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub address: Address,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationId>,
}

#[derive(Debug)]
pub enum GatewayRequest {
    Info(GatewayRequestInner<InfoPayload>),
    RegisterFederation(GatewayRequestInner<RegisterFedPayload>),
    ReceivePayment(GatewayRequestInner<ReceivePaymentPayload>),
    PayInvoice(GatewayRequestInner<PayInvoicePayload>),
    Balance(GatewayRequestInner<BalancePayload>),
    DepositAddress(GatewayRequestInner<DepositAddressPayload>),
    Deposit(GatewayRequestInner<DepositPayload>),
    Withdraw(GatewayRequestInner<WithdrawPayload>),
}

#[derive(Debug)]
pub struct GatewayRequestInner<R: GatewayRequestTrait> {
    request: R,
    sender: oneshot::Sender<Result<R::Response>>,
}

pub trait GatewayRequestTrait {
    type Response;

    fn to_enum(self, sender: oneshot::Sender<Result<Self::Response>>) -> GatewayRequest;
}

macro_rules! impl_gateway_request_trait {
    ($req:ty, $res:ty, $variant:expr) => {
        impl GatewayRequestTrait for $req {
            type Response = $res;
            fn to_enum(self, sender: oneshot::Sender<Result<Self::Response>>) -> GatewayRequest {
                $variant(GatewayRequestInner {
                    request: self,
                    sender,
                })
            }
        }
    };
}

impl_gateway_request_trait!(InfoPayload, GatewayInfo, GatewayRequest::Info);
impl_gateway_request_trait!(RegisterFedPayload, (), GatewayRequest::RegisterFederation);
impl_gateway_request_trait!(
    ReceivePaymentPayload,
    Preimage,
    GatewayRequest::ReceivePayment
);
impl_gateway_request_trait!(PayInvoicePayload, (), GatewayRequest::PayInvoice);
impl_gateway_request_trait!(BalancePayload, Amount, GatewayRequest::Balance);
impl_gateway_request_trait!(
    DepositAddressPayload,
    Address,
    GatewayRequest::DepositAddress
);
impl_gateway_request_trait!(DepositPayload, TransactionId, GatewayRequest::Deposit);
impl_gateway_request_trait!(WithdrawPayload, TransactionId, GatewayRequest::Withdraw);

impl<T> GatewayRequestInner<T>
where
    T: GatewayRequestTrait,
    T::Response: std::fmt::Debug,
{
    pub async fn handle<F: Fn(T) -> FF, FF: Future<Output = Result<T::Response>>>(
        self,
        handler: F,
    ) {
        let result = handler(self.request).await;
        if self.sender.send(result).is_err() {
            // TODO: figure out how to log the result
            tracing::error!("Plugin hung up");
        }
    }
}

pub fn serde_hex_deserialize<'d, T: bitcoin::consensus::Decodable, D: Deserializer<'d>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    if d.is_human_readable() {
        let bytes = hex::decode::<String>(Deserialize::deserialize(d)?)
            .map_err(serde::de::Error::custom)?;
        T::consensus_decode(&mut Cursor::new(&bytes))
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    } else {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        T::consensus_decode(&mut Cursor::new(&bytes))
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

pub fn serde_hex_serialize<T: bitcoin::consensus::Encodable, S: Serializer>(
    t: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    T::consensus_encode(t, &mut bytes).map_err(serde::ser::Error::custom)?;

    if s.is_human_readable() {
        s.serialize_str(&hex::encode(bytes))
    } else {
        s.serialize_bytes(&bytes)
    }
}

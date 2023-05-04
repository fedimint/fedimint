pub mod rpc_client;
pub mod rpc_server;

use std::borrow::Cow;
use std::io::Cursor;

use anyhow::{anyhow, Error};
use bitcoin::{Address, Transaction};
use bitcoin_hashes::hex::{FromHex, ToHex};
use fedimint_client_legacy::ln::PayInvoicePayload;
use fedimint_core::config::FederationId;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{Amount, TransactionId};
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_common::{serde_routing_fees, LightningGateway};
use futures::Future;
use lightning::routing::gossip::RoutingFees;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::{Gateway, GatewayError, LightningMode, Result};

#[derive(Debug, Clone)]
pub struct GatewayRpcSender {
    sender: mpsc::Sender<GatewayRequest>,
}

/// A two-way rpc channel for [`GatewayRequest`]s.
///
/// The channel consists of a long lived sender and receiver used to pass along
/// the original message And a short lived (oneshot tx, rx) is used to receive a
/// response in the opposite direction as the original message.
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

        if let Err(e) = self.sender.send(msg).await {
            error!("Failed to send message over channel: {}", e);
            return Err(e.into());
        }

        receiver
            .await
            .unwrap_or_else(|_| {
                Err(GatewayError::Other(anyhow!(
                    "Failed to receive response over channel"
                )))
            })
            .map_err(|e| e.into())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectFedPayload {
    pub connect: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoPayload {
    pub federation_id: Option<FederationId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestorePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LightningReconnectPayload {
    // Sending `None` for node_type will be interpreted as just reconnecting using the existing
    // settings
    pub node_type: Option<LightningMode>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BalancePayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepositAddressPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepositPayload {
    pub federation_id: FederationId,
    pub txout_proof: TxOutProof,
    #[serde(
        deserialize_with = "serde_hex_deserialize",
        serialize_with = "serde_hex_serialize"
    )]
    pub transaction: Transaction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawPayload {
    pub federation_id: FederationId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub address: Address,
}

/// Information about one of the feds we are connected to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationInfo {
    /// Unique identifier of the fed
    pub federation_id: FederationId,
    /// Information we registered with the fed
    pub registration: LightningGateway,
    /// The current federation balance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<Amount>,
}

impl FederationInfo {
    pub fn new(federation_id: FederationId, registration: LightningGateway) -> Self {
        FederationInfo {
            federation_id,
            registration,
            balance: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationInfo>,
    pub lightning_pub_key: String,
    pub lightning_alias: String,
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
}

#[derive(Debug)]
pub enum GatewayRequest {
    Info(GatewayRequestInner<InfoPayload>),
    ConnectFederation(GatewayRequestInner<ConnectFedPayload>),
    PayInvoice(GatewayRequestInner<PayInvoicePayload>),
    Balance(GatewayRequestInner<BalancePayload>),
    DepositAddress(GatewayRequestInner<DepositAddressPayload>),
    Deposit(GatewayRequestInner<DepositPayload>),
    Withdraw(GatewayRequestInner<WithdrawPayload>),
    Backup(GatewayRequestInner<BackupPayload>),
    Restore(GatewayRequestInner<RestorePayload>),
    LightningReconnect(GatewayRequestInner<LightningReconnectPayload>),
    Shutdown,
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
impl_gateway_request_trait!(
    ConnectFedPayload,
    FederationInfo,
    GatewayRequest::ConnectFederation
);
impl_gateway_request_trait!(PayInvoicePayload, Preimage, GatewayRequest::PayInvoice);
impl_gateway_request_trait!(BalancePayload, Amount, GatewayRequest::Balance);
impl_gateway_request_trait!(
    DepositAddressPayload,
    Address,
    GatewayRequest::DepositAddress
);
impl_gateway_request_trait!(DepositPayload, TransactionId, GatewayRequest::Deposit);
impl_gateway_request_trait!(WithdrawPayload, TransactionId, GatewayRequest::Withdraw);
impl_gateway_request_trait!(BackupPayload, (), GatewayRequest::Backup);
impl_gateway_request_trait!(RestorePayload, (), GatewayRequest::Restore);
impl_gateway_request_trait!(
    LightningReconnectPayload,
    (),
    GatewayRequest::LightningReconnect
);

impl<T> GatewayRequestInner<T>
where
    T: GatewayRequestTrait,
    T::Response: std::fmt::Debug,
{
    pub async fn handle<
        'gateway,
        F: Fn(&'gateway mut Gateway, T) -> FF,
        FF: Future<Output = Result<T::Response>> + Send + 'gateway,
    >(
        self,
        gateway: &'gateway mut Gateway,
        handler: F,
    ) {
        let result = handler(gateway, self.request).await;
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
        let hex_str: Cow<str> = Deserialize::deserialize(d)?;
        let bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        T::consensus_decode(&mut Cursor::new(&bytes)).map_err(serde::de::Error::custom)
    } else {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        T::consensus_decode(&mut Cursor::new(&bytes)).map_err(serde::de::Error::custom)
    }
}

pub fn serde_hex_serialize<T: bitcoin::consensus::Encodable, S: Serializer>(
    t: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    T::consensus_encode(t, &mut bytes).map_err(serde::ser::Error::custom)?;

    if s.is_human_readable() {
        s.serialize_str(&bytes.to_hex())
    } else {
        s.serialize_bytes(&bytes)
    }
}

pub mod rpc_client;
pub mod rpc_server;

use std::borrow::Cow;
use std::io::Cursor;

use bitcoin::{Address, Txid};
use bitcoin_hashes::hex::{FromHex, ToHex};
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::task::TaskGroup;
use fedimint_core::Amount;
use fedimint_ln_client::contracts::Preimage;
use fedimint_ln_client::pay::PayInvoicePayload;
use fedimint_ln_common::{route_hints, serde_option_routing_fees};
use futures::Future;
use lightning::routing::gossip::RoutingFees;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::oneshot;

use crate::{Gateway, Result};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectFedPayload {
    pub invite_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoPayload;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub federation_id: FederationId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestorePayload {
    pub federation_id: FederationId,
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
pub struct WithdrawPayload {
    pub federation_id: FederationId,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
    pub address: Address,
}

/// Information about one of the feds we are connected to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationInfo {
    /// Unique identifier of the fed
    pub federation_id: FederationId,
    pub balance_msat: Amount,
    pub config: ClientConfig,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GatewayInfo {
    pub version_hash: String,
    pub federations: Vec<FederationInfo>,
    pub lightning_pub_key: Option<String>,
    pub lightning_alias: Option<String>,
    #[serde(with = "serde_option_routing_fees")]
    pub fees: Option<RoutingFees>,
    pub route_hints: Vec<route_hints::RouteHint>,
    pub gateway_id: secp256k1::PublicKey,
    pub gateway_state: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetConfigurationPayload {
    pub password: Option<String>,
    pub num_route_hints: Option<u32>,
    pub routing_fees: Option<String>,
}

#[derive(Debug)]
pub enum GatewayRequest {
    Info(GatewayRequestInner<InfoPayload>),
    ConnectFederation(GatewayRequestInner<ConnectFedPayload>),
    PayInvoice(GatewayRequestInner<PayInvoicePayload>),
    Balance(GatewayRequestInner<BalancePayload>),
    DepositAddress(GatewayRequestInner<DepositAddressPayload>),
    Withdraw(GatewayRequestInner<WithdrawPayload>),
    Backup(GatewayRequestInner<BackupPayload>),
    Restore(GatewayRequestInner<RestorePayload>),
    Shutdown,
    SetConfiguration(GatewayRequestInner<SetConfigurationPayload>),
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
impl_gateway_request_trait!(WithdrawPayload, Txid, GatewayRequest::Withdraw);
impl_gateway_request_trait!(BackupPayload, (), GatewayRequest::Backup);
impl_gateway_request_trait!(RestorePayload, (), GatewayRequest::Restore);
impl_gateway_request_trait!(
    SetConfigurationPayload,
    (),
    GatewayRequest::SetConfiguration
);

impl<T> GatewayRequestInner<T>
where
    T: GatewayRequestTrait,
    T::Response: std::fmt::Debug,
{
    pub async fn handle<
        'gateway,
        F: Fn(&'gateway mut Gateway, &'gateway mut TaskGroup, T) -> FF,
        FF: Future<Output = Result<T::Response>> + Send + 'gateway,
    >(
        self,
        gateway: &'gateway mut Gateway,
        tg: &'gateway mut TaskGroup,
        handler: F,
    ) {
        let result = handler(gateway, tg, self.request).await;
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

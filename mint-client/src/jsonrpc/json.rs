use crate::jsonrpc::error::RpcError;
use crate::mint::{CoinFinalizationData, SpendableCoin};
use bitcoin::Transaction;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::wallet::txoproof::TxOutProof;
use minimint::outcome::TransactionStatus;
use minimint_api::encoding::Decodable;
use minimint_api::{Amount, OutPoint, TransactionId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::error::Error;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const JSON_RPC: &str = "2.0";
///JSON-RPC Request object
#[derive(Deserialize, Serialize, Debug)]
pub struct Request {
    ///A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
    ///If it's none demand a jsonrpc 2.0 spec. request
    pub jsonrpc: Option<String>,
    ///A String containing the name of the method to be invoked.
    ///Method names that begin with the word rpc followed by a period character (U+002E or ASCII 46) are reserved for rpc-internal methods
    ///and extensions and MUST NOT be used for anything else.
    pub method: String,
    ///A Structured value that holds the parameter values to be used during the invocation of the method. This member MAY be omitted.
    pub params: Value,
    ///An identifier established by the Client that MUST contain a String, Number, or NULL value if included.
    ///If it is not included it is assumed to be a notification. The value SHOULD normally not be Null and Numbers SHOULD NOT contain fractional parts
    pub id: Option<Value>,
}

impl Request {
    pub fn standard<I: Serialize>(method: &str, id: Option<I>) -> Self {
        Self::standard_with_params(method, None::<()>, id)
    }

    pub fn standard_with_params<I: Serialize, P: Serialize>(
        method: &str,
        params: P,
        id: Option<I>,
    ) -> Self {
        Self {
            jsonrpc: Some(JSON_RPC.to_string()),
            method: method.to_string(),
            params: json!(params),
            id: id.map(|i| json!(i)),
        }
    }
}

///JSON-RPC Response object
#[derive(Serialize, Deserialize)]
pub struct Response {
    ///A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
    pub jsonrpc: String,
    ///This member is REQUIRED on success.
    ///This member MUST NOT exist if there was an error invoking the method.
    ///The value of this member is determined by the method invoked on the Server.
    pub result: Option<Value>,
    ///This member is REQUIRED on error.
    ///This member MUST NOT exist if there was no error triggered during invocation.
    ///The value for this member MUST be an Object as defined in section 5.1.
    pub error: Option<RpcError>,
    ///This member is REQUIRED.
    ///It MUST be the same as the value of the id member in the Request Object.
    ///If there was an error in detecting the id in the Request object (e.g. Parse error/Invalid Request), it MUST be Null.
    pub id: Option<Value>,
}
impl Response {
    pub fn with_result(result: Value, id: Value) -> Self {
        Response {
            jsonrpc: JSON_RPC.to_string(),
            result: Some(result),
            error: None,
            id: Some(id),
        }
    }
    pub fn with_error(error: RpcError, id: Option<Value>) -> Self {
        Response {
            jsonrpc: JSON_RPC.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

// -> clientd
/// Holds all possible Responses of the RPC-CLient can also be used to parse responses (for client-cli)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum APIResponse {
    ///The clients holdings : The quantity of coins for each tier. For total holdings sum(Infoi.quantity * Infoi.tier) with i = 0 - n
    /// Also contains the [`PendingRes`] variant.
    Info {
        coins: Vec<CoinsByTier>,
        pending: PendingRes,
    },
    Pending {
        pending: PendingRes,
    },
    ///Holds a new address for the client to use for peg-in
    PegInAddress {
        pegin_address: bitcoin::Address,
    },
    ///Holds a [`minimint_api::TransactionId`] from a successful PegIn or PegOut
    PegIO {
        txid: TransactionId,
    },
    /// Holds the serialized [`Coins<SpendableCoin>`]
    Spend {
        token: Coins<SpendableCoin>,
    },
    /// Holds the from the federation returned [`OutPoint`] (regarding the reissuance) and the [`TransactionStatus`]
    Reissue {
        out_point: OutPoint,
        status: TransactionStatus,
    },
    /// Holds events which could not be sent to the client but were triggered by some action from him. This will be cleared after querying it
    Events {
        events: Vec<Event>,
    },
    /// Represents an empty response
    Empty,
}

/// Active issuances : Not yet (bey the federation) signed BUT accepted coins
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingRes {
    //TODO: Also return Vec<TransactionId> (?)
    transactions: usize,
    acc_qty_coins: usize,
    acc_val_amount: Amount,
}

impl PendingRes {
    pub fn build_pending(all_pending: Vec<CoinFinalizationData>) -> Self {
        let acc_qty_coins = all_pending.iter().map(|cfd| cfd.coin_count()).sum();
        let acc_val_amount = all_pending.iter().map(|cfd| cfd.coin_amount()).sum();
        PendingRes {
            transactions: all_pending.len(),
            acc_qty_coins,
            acc_val_amount,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    timestamp: u64,
    data: String, //use something else than string ?
}

impl Event {
    pub fn build_event(data: String) -> Self {
        let time = SystemTime::now();
        let d = time.duration_since(UNIX_EPOCH).unwrap();
        let timestamp = (d.as_secs() as u64) * 1000 + (u64::from(d.subsec_nanos()) / 1_000_000);
        Event { timestamp, data }
    }
}
/// Stores events (the (un)successful result of some action initiated by a client which couldn't be sent back to him)
/// If the capacity is reached events will be dropped from the back
pub struct EventLog {
    data: Mutex<VecDeque<Event>>,
    capacity: usize,
    //maturity: u64 could be used to drop events with timestamp > maturity <- idea
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        EventLog {
            data: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }
    pub fn add(&self, data: String) {
        let mut events = self.data.lock().unwrap(); // don't know what to do here.. clientd should be restarted if this happens
                                                    //Because Mutex only guarantees that only one thread at a time but not the (in order) correct one is pushing events
                                                    //this guarantees that the timestamps will be sorted
        let event = Event::build_event(data);

        if let Some(ts) = events.back() {
            if event.timestamp < ts.timestamp {
                let len = events.len();
                events.insert(len - 1, event)
            } else {
                events.push_back(event);
            }
        } else {
            events.push_back(event);
        }
        //If the DeQueue gets too long drop the 'oldest' event
        if events.len() > self.capacity {
            events.pop_front();
            events.shrink_to_fit();
        }
    }
    pub fn get(&self, timestamp: u64) -> Vec<Event> {
        let events = self.data.lock().unwrap();
        events
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }
}

/// Holds quantity of coins per tier
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoinsByTier {
    tier: u64,
    quantity: usize,
}
/// To Deserialize a peg-in request
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(from = "PegInReqRaw")]
pub struct PegInReq {
    pub txout_proof: TxOutProof,
    pub transaction: Transaction,
}
#[derive(Deserialize, Clone, Debug)]
pub struct PegInReqRaw {
    pub txout_proof: String,
    pub transaction: String,
}
/// To Deserialize a peg-out request (amount in sat)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PegOutReq {
    pub address: bitcoin::Address,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub amount: bitcoin::Amount,
}
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct InvoiceReq {
    #[serde(with = "crate::ln::serde_invoice")]
    pub bolt11: lightning_invoice::Invoice,
}
impl From<PegInReqRaw> for PegInReq {
    fn from(raw: PegInReqRaw) -> Self {
        PegInReq {
            txout_proof: from_hex(raw.txout_proof.as_str()).unwrap(),
            transaction: from_hex(raw.transaction.as_str()).unwrap(),
        }
    }
}

fn from_hex<D: Decodable>(s: &str) -> Result<D, Box<dyn Error>> {
    let bytes = hex::decode(s)?;
    Ok(D::consensus_decode(std::io::Cursor::new(bytes))?)
}
impl APIResponse {
    /// Builds the [`APIResponse::Info`] variant.
    pub fn build_info(coins: Coins<SpendableCoin>, cfd: Vec<CoinFinalizationData>) -> Self {
        let info_coins: Vec<CoinsByTier> = coins
            .coins
            .iter()
            .map(|(tier, c)| CoinsByTier {
                quantity: c.len(),
                tier: tier.milli_sat,
            })
            .collect();
        APIResponse::Info {
            coins: info_coins,
            pending: PendingRes::build_pending(cfd),
        }
    }
    /// Builds the [`APIResponse::Spend`] variant.
    pub fn build_spend(token: Coins<SpendableCoin>) -> Self {
        APIResponse::Spend { token }
    }
    /// Builds the [`APIResponse::Reissue`] variant.
    pub fn build_reissue(out_point: OutPoint, status: TransactionStatus) -> Self {
        APIResponse::Reissue { out_point, status }
    }
    /// Builds the [`APIResponse::Events`] variant.
    pub fn build_events(events: Vec<Event>) -> Self {
        APIResponse::Events { events }
    }
}
// <- clientd

/*
Copyright (C) 2007-2010 by the JSON-RPC Working Group

This document and translations of it may be used to implement JSON-RPC, it may be copied and furnished to others, and derivative works that comment on or otherwise explain it or assist in its implementation may be prepared, copied, published and distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice and this paragraph are included on all such copies and derivative works. However, this document itself may not bemodified in any way.

The limited permissions granted above are perpetual and will not be revoked.

This document and the information contained herein is provided "AS IS" and ALL WARRANTIES, EXPRESS OR IMPLIED are DISCLAIMED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 */
use crate::clients::user::APIResponse;
use crate::mint::{CoinFinalizationData, SpendableCoin};
use crate::{LightningGateway, UserClient};
use futures::future::BoxFuture;
use minimint::modules::mint::tiered::coins::Coins;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

const JSON_RPC: &str = "2.0";
///JSON-RPC Request object
#[derive(Deserialize)]
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
    ///If it is not included it is assumed to be a notification. The value SHOULD normally not be Null [1] and Numbers SHOULD NOT contain fractional parts [2]
    pub id: Value,
}
///JSON-RPC Response object
#[derive(Serialize)]
pub struct Response<'a> {
    ///A String specifying the version of the JSON-RPC protocol. MUST be exactly "2.0".
    pub jsonrpc: &'a str,
    ///This member is REQUIRED on success.
    ///This member MUST NOT exist if there was an error invoking the method.
    ///The value of this member is determined by the method invoked on the Server.
    pub result: Value,
    ///This member is REQUIRED on error.
    ///This member MUST NOT exist if there was no error triggered during invocation.
    ///The value for this member MUST be an Object as defined in section 5.1.
    pub error: Value, //TODO: Use a custom Error instead
    ///This member is REQUIRED.
    ///It MUST be the same as the value of the id member in the Request Object.
    ///If there was an error in detecting the id in the Request object (e.g. Parse error/Invalid Request), it MUST be Null.
    pub id: Value,
}

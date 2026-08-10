use bech32::{Bech32, Hrp};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
/// Generic LNURL response wrapper that handles the error case.
/// Successful responses deserialize directly into `Ok(T)`, while error
/// responses with `{"status": "ERROR", "reason": "..."}` fall back to `Error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LnurlResponse<T> {
    Ok(T),
    Error { status: String, reason: String },
}

impl<T> LnurlResponse<T> {
    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            status: "ERROR".to_string(),
            reason: reason.into(),
        }
    }

    pub fn into_result(self) -> Result<T, String> {
        match self {
            Self::Ok(data) => Ok(data),
            Self::Error { reason, .. } => Err(reason),
        }
    }
}

/// Decode a bech32-encoded LNURL string to a URL string
pub fn parse_lnurl(s: &str) -> Option<String> {
    let (hrp, data) = bech32::decode(&s.to_lowercase()).ok()?;

    if hrp.as_str() != "lnurl" {
        return None;
    }

    String::from_utf8(data).ok()
}

/// Encode a URL as a bech32 LNURL string
pub fn encode_lnurl(url: &str) -> String {
    bech32::encode::<Bech32>(Hrp::parse("lnurl").expect("valid hrp"), url.as_bytes())
        .expect("encoding succeeds")
}

/// Parse a lightning address (user@domain) to its LNURL-pay endpoint URL
pub fn parse_address(s: &str) -> Option<String> {
    let (user, domain) = s.split_once('@')?;

    if user.is_empty() || domain.is_empty() {
        return None;
    }

    Some(format!("https://{domain}/.well-known/lnurlp/{user}"))
}

pub fn pay_request_tag() -> String {
    "payRequest".to_string()
}

/// LNURL-pay response (LUD-06)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayResponse {
    pub tag: String,
    pub callback: String,
    pub metadata: String,
    pub min_sendable: u64,
    pub max_sendable: u64,
}

/// Response when requesting an invoice from LNURL-pay callback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceResponse {
    /// The BOLT11 invoice
    pub pr: Bolt11Invoice,
    /// LUD-21 verify URL
    pub verify: Option<String>,
}

/// LUD-21 verify response
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub settled: bool,
    #[serde_as(as = "Option<Hex>")]
    pub preimage: Option<[u8; 32]>,
}

/// Fetch and parse an LNURL-pay response
pub async fn request(url: &str) -> Result<PayResponse, String> {
    let response = reqwest::get(url)
        .await
        .map_err(|_| "Failed to fetch lnurl pay response".to_string())?
        .json::<LnurlResponse<PayResponse>>()
        .await
        .map_err(|_| "Failed to parse lnurl pay response".to_string())?
        .into_result()?;

    Ok(response)
}

/// Fetch an invoice from an LNURL-pay callback
pub async fn get_invoice(
    response: &PayResponse,
    amount_msat: u64,
) -> Result<InvoiceResponse, String> {
    if amount_msat < response.min_sendable {
        return Err(format!(
            "Minimum amount is {} sats",
            response.min_sendable / 1000
        ));
    }

    if amount_msat > response.max_sendable {
        return Err(format!(
            "Maximum amount is {} sats",
            response.max_sendable / 1000
        ));
    }

    let separator = if response.callback.contains('?') {
        '&'
    } else {
        '?'
    };

    let callback_url = format!("{}{}amount={}", response.callback, separator, amount_msat);

    let invoice = reqwest::get(callback_url)
        .await
        .map_err(|_| "Failed to fetch lnurl callback response".to_string())?
        .json::<LnurlResponse<InvoiceResponse>>()
        .await
        .map_err(|_| "Failed to parse lnurl callback response".to_string())?
        .into_result()?;

    if invoice.pr.amount_milli_satoshis() != Some(amount_msat) {
        return Err("Invoice amount does not match requested amount".to_string());
    }

    Ok(invoice)
}

/// Verify a payment using LUD-21
pub async fn verify_invoice(url: &str) -> Result<VerifyResponse, String> {
    reqwest::get(url)
        .await
        .map_err(|_| "Failed to fetch lnurl verify response".to_string())?
        .json::<LnurlResponse<VerifyResponse>>()
        .await
        .map_err(|_| "Failed to parse lnurl verify response".to_string())?
        .into_result()
}

#[test]
fn parse_lnurl_official_test_vector_lud_01() {
    let lnurl = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";
    let expected = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";

    assert_eq!(parse_lnurl(lnurl).unwrap(), expected);
}

#[test]
fn parse_pay_response_lud_06() {
    let json = r#"{
        "callback": "https://example.com/lnurl/pay/callback",
        "maxSendable": 100000000,
        "minSendable": 1000,
        "metadata": "[[\"text/plain\",\"Pay to example.com\"]]",
        "tag": "payRequest"
    }"#;

    let response: LnurlResponse<PayResponse> = serde_json::from_str(json).unwrap();

    let pay = response.into_result().unwrap();

    assert_eq!(pay.tag, "payRequest");
    assert_eq!(pay.callback, "https://example.com/lnurl/pay/callback");
    assert_eq!(pay.min_sendable, 1000);
    assert_eq!(pay.max_sendable, 100000000);
}

#[test]
fn parse_error_response() {
    let json = r#"{"status": "ERROR", "reason": "Invalid request"}"#;

    let response: LnurlResponse<PayResponse> = serde_json::from_str(json).unwrap();

    assert_eq!(response.into_result().unwrap_err(), "Invalid request");
}

#[test]
fn parse_verify_response_lud_21() {
    let json = r#"{
        "status": "OK",
        "settled": true,
        "preimage": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }"#;

    let response: LnurlResponse<VerifyResponse> = serde_json::from_str(json).unwrap();

    let verify = response.into_result().unwrap();

    assert!(verify.settled);
    assert!(verify.preimage.is_some());
}

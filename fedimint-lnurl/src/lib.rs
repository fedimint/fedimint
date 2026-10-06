use bech32::{Bech32, Hrp};
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum LnurlError {
    #[error("Failed to fetch LNURL response: {0}")]
    FetchError(String),
    #[error("Failed to parse LNURL response JSON: {0}")]
    ParseError(String),
    #[error("LNURL server error: {0}")]
    ServerError(String),
    #[error("Invalid lightning address: {0}")]
    InvalidAddress(String),
    #[error("Expected tag '{expected}' but got '{got}'")]
    UnexpectedTag { expected: String, got: String },
    #[error("Amount {amount} msat is outside valid range [{min}, {max}]")]
    InvalidAmount {
        amount: u64,
        min: u64,
        max: u64,
    },
    #[error("Invoice amount mismatch: expected {expected} msat, got {got}")]
    AmountMismatch { expected: u64, got: String },
    #[error("Metadata hash verification failed")]
    InvalidMetadataHash,
    #[error("HTTP error {status}: {body}")]
    HttpError { status: u16, body: String },
}

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

    pub fn into_lnurl_result(self) -> Result<T, LnurlError> {
        match self {
            Self::Ok(data) => Ok(data),
            Self::Error { reason, .. } => Err(LnurlError::ServerError(reason)),
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

fn is_valid_hostname(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }

    for c in domain.chars() {
        match c {
            '/' | '?' | '#' | '@' | ' ' | '\t' | '\n' | '\r' => return false,
            _ => {}
        }
    }

    true
}

const LUD16_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

fn is_valid_lud16_local_part(user: &str) -> bool {
    if user.is_empty() {
        return false;
    }

    user.chars().all(|c| LUD16_CHARSET.contains(c))
}

/// Parse a lightning address (user@domain) to its LNURL-pay endpoint URL.
/// Validates both user and domain parts according to LUD-16 and hostname rules.
pub fn parse_address(s: &str) -> Option<String> {
    let (user, domain) = s.rsplit_once('@')?;

    if !is_valid_lud16_local_part(user) || !is_valid_hostname(domain) {
        return None;
    }

    Some(format!("https://{domain}/.well-known/lnurlp/{user}"))
}

/// Parse a lightning address with detailed error information.
pub fn parse_address_result(s: &str) -> Result<String, LnurlError> {
    let (user, domain) = s.rsplit_once('@').ok_or_else(|| {
        LnurlError::InvalidAddress("Missing '@' separator".to_string())
    })?;

    if !is_valid_lud16_local_part(user) {
        return Err(LnurlError::InvalidAddress(
            format!("Invalid local part '{}'. Must contain only alphanumeric, '.', '-', or '_'", user),
        ));
    }

    if !is_valid_hostname(domain) {
        return Err(LnurlError::InvalidAddress(
            format!("Invalid domain '{}'. Must be a valid hostname", domain),
        ));
    }

    Ok(format!("https://{domain}/.well-known/lnurlp/{user}"))
}

pub fn pay_request_tag() -> String {
    "payRequest".to_string()
}

pub fn withdraw_request_tag() -> String {
    "withdrawRequest".to_string()
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

/// Compute the SHA-256 hash of metadata string (LUD-06 h tag).
pub fn metadata_hash(metadata: &str) -> [u8; 32] {
    Sha256Hash::hash(metadata.as_bytes()).to_byte_array()
}

/// Verify that an invoice's h tag matches the metadata hash (LUD-06).
pub fn verify_metadata_hash(invoice: &Bolt11Invoice, metadata: &str) -> Result<(), LnurlError> {
    let expected_hash = metadata_hash(metadata);
    let invoice_hash_bytes = invoice.payment_hash().as_ref();

    if invoice_hash_bytes != expected_hash {
        return Err(LnurlError::InvalidMetadataHash);
    }

    Ok(())
}

/// Fetch and parse an LNURL-pay response (legacy string-returning version).
/// Prefer `request_with_client` for production use.
pub async fn request(url: &str) -> Result<PayResponse, String> {
    match request_with_client(url, &reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?)
    .await
    {
        Ok(resp) => Ok(resp),
        Err(e) => Err(e.to_string()),
    }
}

/// Fetch and parse an LNURL-pay response with proper error handling.
pub async fn request_with_client(
    url: &str,
    client: &reqwest::Client,
) -> Result<PayResponse, LnurlError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| LnurlError::FetchError(e.to_string()))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .unwrap_or_else(|_| "(unable to read body)".to_string());

    if !status.is_success() {
        return Err(LnurlError::HttpError {
            status: status.as_u16(),
            body: body_text,
        });
    }

    let response: LnurlResponse<PayResponse> = serde_json::from_str(&body_text)
        .map_err(|e| LnurlError::ParseError(e.to_string()))?;

    let pay_response = response.into_lnurl_result()?;

    if pay_response.tag != "payRequest" {
        return Err(LnurlError::UnexpectedTag {
            expected: "payRequest".to_string(),
            got: pay_response.tag.clone(),
        });
    }

    Ok(pay_response)
}

/// Fetch an invoice from an LNURL-pay callback (legacy string-returning version).
/// Prefer `get_invoice_with_client` for production use.
pub async fn get_invoice(
    response: &PayResponse,
    amount_msat: u64,
) -> Result<InvoiceResponse, String> {
    match get_invoice_with_client(
        response,
        amount_msat,
        &reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
        false,
    )
    .await
    {
        Ok(inv) => Ok(inv),
        Err(e) => Err(e.to_string()),
    }
}

/// Fetch an invoice from an LNURL-pay callback with proper error handling.
/// If `verify_metadata_hash` is true, validates the invoice's h tag against metadata.
pub async fn get_invoice_with_client(
    response: &PayResponse,
    amount_msat: u64,
    client: &reqwest::Client,
    verify_hash: bool,
) -> Result<InvoiceResponse, LnurlError> {
    if amount_msat < response.min_sendable {
        return Err(LnurlError::InvalidAmount {
            amount: amount_msat,
            min: response.min_sendable,
            max: response.max_sendable,
        });
    }

    if amount_msat > response.max_sendable {
        return Err(LnurlError::InvalidAmount {
            amount: amount_msat,
            min: response.min_sendable,
            max: response.max_sendable,
        });
    }

    let separator = if response.callback.contains('?') {
        '&'
    } else {
        '?'
    };

    let callback_url = format!("{}{}amount={}", response.callback, separator, amount_msat);

    let resp = client
        .get(&callback_url)
        .send()
        .await
        .map_err(|e| LnurlError::FetchError(e.to_string()))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .unwrap_or_else(|_| "(unable to read body)".to_string());

    if !status.is_success() {
        return Err(LnurlError::HttpError {
            status: status.as_u16(),
            body: body_text,
        });
    }

    let invoice_response: LnurlResponse<InvoiceResponse> = serde_json::from_str(&body_text)
        .map_err(|e| LnurlError::ParseError(e.to_string()))?;

    let invoice = invoice_response.into_lnurl_result()?;

    if invoice.pr.amount_milli_satoshis() != Some(amount_msat) {
        return Err(LnurlError::AmountMismatch {
            expected: amount_msat,
            got: match invoice.pr.amount_milli_satoshis() {
                Some(amt) => format!("{} msat", amt),
                None => "no amount".to_string(),
            },
        });
    }

    if verify_hash {
        crate::verify_metadata_hash(&invoice.pr, &response.metadata)?;
    }

    Ok(invoice)
}

/// Verify a payment using LUD-21 (legacy string-returning version).
/// Prefer `verify_invoice_with_client` for production use.
pub async fn verify_invoice(url: &str) -> Result<VerifyResponse, String> {
    match verify_invoice_with_client(
        url,
        &reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
    )
    .await
    {
        Ok(v) => Ok(v),
        Err(e) => Err(e.to_string()),
    }
}

/// Verify a payment using LUD-21 with proper error handling.
pub async fn verify_invoice_with_client(
    url: &str,
    client: &reqwest::Client,
) -> Result<VerifyResponse, LnurlError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| LnurlError::FetchError(e.to_string()))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .unwrap_or_else(|_| "(unable to read body)".to_string());

    if !status.is_success() {
        return Err(LnurlError::HttpError {
            status: status.as_u16(),
            body: body_text,
        });
    }

    let response: LnurlResponse<VerifyResponse> = serde_json::from_str(&body_text)
        .map_err(|e| LnurlError::ParseError(e.to_string()))?;

    response.into_lnurl_result()
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

#[test]
fn test_valid_lightning_address() {
    assert_eq!(
        parse_address("user@example.com"),
        Some("https://example.com/.well-known/lnurlp/user".to_string())
    );
}

#[test]
fn test_lightning_address_with_hyphen_and_dot() {
    assert_eq!(
        parse_address("user.name-test@example.co.uk"),
        Some("https://example.co.uk/.well-known/lnurlp/user.name-test".to_string())
    );
}

#[test]
fn test_invalid_address_with_slash() {
    assert_eq!(parse_address("user@example.com/other"), None);
}

#[test]
fn test_invalid_address_with_query() {
    assert_eq!(parse_address("user@example.com?query=1"), None);
}

#[test]
fn test_invalid_address_with_fragment() {
    assert_eq!(parse_address("user@example.com#fragment"), None);
}

#[test]
fn test_invalid_address_with_double_at() {
    // Correctly rejects addresses with @ in the local part after splitting on last @
    assert_eq!(parse_address("a@b@host"), None);
}

#[test]
fn test_invalid_local_part() {
    assert_eq!(parse_address("user!@example.com"), None);
}

#[test]
fn test_metadata_hash() {
    let metadata = "[[\"text/plain\",\"Pay to example.com\"]]";
    let hash = metadata_hash(metadata);
    assert_eq!(hash.len(), 32);
}

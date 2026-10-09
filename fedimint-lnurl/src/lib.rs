use bech32::{Bech32, Hrp};
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use bitcoin_hashes::Hash;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use thiserror::Error;
#[cfg(test)]
use {
    bitcoin::secp256k1::{Secp256k1, SecretKey},
    lightning_invoice::{
        Bolt11InvoiceDescription, Currency, Description, InvoiceBuilder, PaymentSecret, Sha256,
    },
};

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
    /// Vestigial routing hints, always empty in practice, but required by
    /// LUD-06. Defaulted when parsing since not all services send it.
    #[serde(default)]
    pub routes: Vec<serde_json::Value>,
    /// LUD-21 verify URL
    pub verify: Option<String>,
}

/// LUD-21 verify response
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Always "OK" for successful responses per LUD-21. Defaulted when
    /// parsing since not all services send it.
    #[serde(default = "ok_status")]
    pub status: String,
    pub settled: bool,
    #[serde_as(as = "Option<Hex>")]
    pub preimage: Option<[u8; 32]>,
}

fn ok_status() -> String {
    "OK".to_string()
}

<<<<<<< HEAD
/// Verify that an invoice's description hash commits to the metadata (LUD-06).
///
/// The commitment is the BOLT11 description hash, not the payment hash, which
/// is the hash of the preimage and says nothing about the metadata. An invoice
/// without a description hash cannot be verified, so it is rejected.
pub fn verify_metadata_hash(invoice: &Bolt11Invoice, metadata: &str) -> Result<(), LnurlError> {
    let expected_hash = Sha256Hash::hash(metadata.as_bytes());

    match invoice.description() {
        Bolt11InvoiceDescriptionRef::Hash(description_hash)
            if description_hash.0 == expected_hash =>
        {
            Ok(())
        }
        _ => Err(LnurlError::InvalidMetadataHash),
    }
=======
impl VerifyResponse {
    /// A LUD-21 response for a payment that has been settled
    pub fn settled(preimage: [u8; 32]) -> Self {
        Self {
            status: ok_status(),
            settled: true,
            preimage: Some(preimage),
        }
    }

    /// A LUD-21 response for a payment that is still pending
    pub fn pending() -> Self {
        Self {
            status: ok_status(),
            settled: false,
            preimage: None,
        }
    }
>>>>>>> 9479309dea5010bc14eccf016516cc934101b935
}

/// Fetch and parse an LNURL-pay response
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
fn serialize_invoice_response_lud_06() {
    let invoice = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0";

    let response = InvoiceResponse {
        pr: invoice.parse().unwrap(),
        routes: vec![],
        verify: Some("https://example.com/verify/abc".to_string()),
    };

    let json = serde_json::to_value(LnurlResponse::Ok(response)).unwrap();

    assert_eq!(json["pr"], invoice);
    // LUD-06 requires the routes field to be present as an empty array
    assert_eq!(json["routes"], serde_json::json!([]));
    assert_eq!(json["verify"], "https://example.com/verify/abc");
}

#[test]
fn parse_invoice_response_without_routes() {
    let json = r#"{
        "pr": "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0",
        "verify": null
    }"#;

    let response: LnurlResponse<InvoiceResponse> = serde_json::from_str(json).unwrap();

    let invoice = response.into_result().unwrap();

    assert!(invoice.routes.is_empty());
    assert!(invoice.verify.is_none());
}

#[test]
fn parse_error_response() {
    let json = r#"{"status": "ERROR", "reason": "Invalid request"}"#;

    let response: LnurlResponse<PayResponse> = serde_json::from_str(json).unwrap();

    assert_eq!(response.into_result().unwrap_err(), "Invalid request");
}

#[test]
fn serialize_verify_response_lud_21() {
    let json = serde_json::to_value(LnurlResponse::Ok(VerifyResponse::pending())).unwrap();

    // LUD-21 responses carry an explicit "OK" status alongside the payment
    // state
    assert_eq!(json["status"], "OK");
    assert_eq!(json["settled"], false);
    assert_eq!(json["preimage"], serde_json::Value::Null);

    let json =
        serde_json::to_value(LnurlResponse::Ok(VerifyResponse::settled([0x42; 32]))).unwrap();

    assert_eq!(json["status"], "OK");
    assert_eq!(json["settled"], true);
    assert_eq!(json["preimage"], "42".repeat(32));
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

#[cfg(test)]
const TEST_METADATA: &str = "[[\"text/plain\",\"Pay to example.com\"]]";

/// Signs an invoice with a fixed key. Its payment hash is deliberately unrelated
/// to the metadata, so only the description commitment can satisfy the check.
#[cfg(test)]
fn signed_invoice(description: Bolt11InvoiceDescription) -> Bolt11Invoice {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[0x11; 32]).expect("valid secret key");

    InvoiceBuilder::new(Currency::Bitcoin)
        .invoice_description(description)
        .payment_hash(Sha256Hash::hash(&[0x22; 32]))
        .payment_secret(PaymentSecret([0x33; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .expect("invoice builds")
}

#[test]
fn verify_metadata_hash_accepts_matching_description_hash() {
    let invoice = signed_invoice(Bolt11InvoiceDescription::Hash(Sha256(Sha256Hash::hash(
        TEST_METADATA.as_bytes(),
    ))));

    assert!(verify_metadata_hash(&invoice, TEST_METADATA).is_ok());
}

#[test]
fn verify_metadata_hash_rejects_mismatched_description_hash() {
    let invoice = signed_invoice(Bolt11InvoiceDescription::Hash(Sha256(Sha256Hash::hash(
        b"some other metadata",
    ))));

    assert!(matches!(
        verify_metadata_hash(&invoice, TEST_METADATA),
        Err(LnurlError::InvalidMetadataHash)
    ));
}

#[test]
fn verify_metadata_hash_rejects_missing_description_hash() {
    let invoice = signed_invoice(Bolt11InvoiceDescription::Direct(
        Description::new("Pay to example.com".to_string()).expect("description fits"),
    ));

    assert!(matches!(
        verify_metadata_hash(&invoice, TEST_METADATA),
        Err(LnurlError::InvalidMetadataHash)
    ));
}

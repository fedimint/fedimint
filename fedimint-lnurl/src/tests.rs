use super::{encode_lnurl, parse_lnurl};

/// Long enough that the encoded LNURL exceeds the 1023 character bech32 code
/// length.
fn long_url() -> String {
    format!("https://example.com/pay/{}", "a".repeat(700))
}

#[test]
fn encode_lnurl_roundtrips_urls_beyond_the_bech32_code_length() {
    let url = long_url();
    let lnurl = encode_lnurl(&url);

    assert!(lnurl.len() > 1023, "encoded length {}", lnurl.len());
    assert_eq!(parse_lnurl(&lnurl).as_deref(), Some(url.as_str()));
    assert_eq!(
        parse_lnurl(&lnurl.to_uppercase()).as_deref(),
        Some(url.as_str())
    );
}

#[test]
fn parse_lnurl_rejects_a_corrupted_long_lnurl() {
    let mut lnurl = encode_lnurl(&long_url());
    let last = lnurl.pop().expect("encoded LNURL is not empty");
    lnurl.push(if last == 'q' { 'p' } else { 'q' });

    assert_eq!(parse_lnurl(&lnurl), None);
}

#[test]
fn parse_lnurl_rejects_other_hrps() {
    let url = "https://example.com";
    let lnurl = encode_lnurl(url);
    let other = bech32::encode::<bech32::Bech32>(
        bech32::Hrp::parse("lnurx").expect("valid hrp"),
        url.as_bytes(),
    )
    .expect("short enough for bech32");

    assert_eq!(parse_lnurl(&lnurl).as_deref(), Some(url));
    assert_eq!(parse_lnurl(&other), None);
}

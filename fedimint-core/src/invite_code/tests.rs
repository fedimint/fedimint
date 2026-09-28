use std::str::FromStr;

use fedimint_core::PeerId;
use fedimint_core::base32::FEDIMINT_PREFIX;

use super::{BECH32_HRP, InviteCodeParseError};
use crate::config::FederationId;
use crate::invite_code::InviteCode;

#[test]
fn test_invite_code_to_from_string() {
    let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
    let invite_code = InviteCode::from_str(invite_code_str).expect("valid invite code");

    InviteCode::from_str(&crate::base32::encode_prefixed(
        FEDIMINT_PREFIX,
        &invite_code,
    ))
    .expect("Failed to parse base 32 invite code");

    assert_eq!(invite_code.to_string(), invite_code_str);
    assert_eq!(
        invite_code.0,
        [
            crate::invite_code::InviteCodePart::Api {
                url: "wss://fedimintd.mplsfed.foo/".parse().expect("valid url"),
                peer: PeerId::new(0),
            },
            crate::invite_code::InviteCodePart::FederationId(FederationId(
                bitcoin::hashes::sha256::Hash::from_str(
                    "bea7ff4116f2b1d324c7b5d699cce4ac7408cee41db2c88027e21b76fff3b9f4"
                )
                .expect("valid hash")
            ))
        ]
    );
}

#[test]
fn from_str_rejects_wrong_hrp() {
    let other_hrp = bech32::Hrp::parse("abcd").expect("valid hrp");
    let encoded = bech32::encode::<bech32::Bech32m>(other_hrp, &[0u8; 8]).expect("encodes");
    assert!(matches!(
        InviteCode::from_str(&encoded),
        Err(InviteCodeParseError::InvalidHrp { hrp }) if hrp == other_hrp
    ));
}

#[test]
fn from_str_reports_the_whole_decode_chain_for_a_truncated_payload() {
    use crate::encoding::Encodable;
    use crate::util::FmtCompact as _;

    // Dropping the last byte of a valid invite code cuts off mid-federation-id, so
    // the reader runs out of input partway through the consensus decode instead of
    // failing on the very first byte.
    let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
    let invite = InviteCode::from_str(invite_code_str).expect("valid invite code");
    let bytes = invite.consensus_encode_to_vec();
    let encoded =
        bech32::encode::<bech32::Bech32m>(BECH32_HRP, &bytes[..bytes.len() - 1]).expect("encodes");

    let err = InviteCode::from_str(&encoded).expect_err("payload is truncated");
    let text = err.to_string();
    let InviteCodeParseError::Decode(inner) = err else {
        panic!("a truncated payload is a decode error: {err:?}");
    };

    assert_eq!(
        text,
        format!("Invalid invite code payload: {}", inner.fmt_compact())
    );
    assert_ne!(
        inner.fmt_compact().to_string(),
        inner.to_string(),
        "the decode error has more than one layer, and the message shows all of them"
    );
}

#[test]
fn from_str_reports_the_whole_decode_chain_for_a_truncated_prefixed_payload() {
    use crate::base32::PrefixedDecodeError;
    use crate::encoding::Encodable;
    use crate::util::FmtCompact as _;

    // Same truncation as the bech32 case above, but the payload carries the
    // FEDIMINT_PREFIX and is base32-encoded instead of bech32-encoded.
    let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
    let invite = InviteCode::from_str(invite_code_str).expect("valid invite code");
    let bytes = invite.consensus_encode_to_vec();
    let encoded = crate::base32::encode_prefixed_bytes(FEDIMINT_PREFIX, &bytes[..bytes.len() - 1]);

    let err = InviteCode::from_str(&encoded).expect_err("payload is truncated");
    let text = err.to_string();
    let err_fmt_compact = err.fmt_compact().to_string();
    let InviteCodeParseError::Base32(PrefixedDecodeError::ConsensusDecode(inner)) = err else {
        panic!("a truncated payload is a decode error: {err:?}");
    };

    assert_eq!(
        text,
        format!(
            "Invalid prefixed base32 invite code: \
             Invalid consensus encoding in base32 payload: {}",
            inner.fmt_compact()
        )
    );
    assert_eq!(
        err_fmt_compact, text,
        "no source, so nothing is printed twice"
    );
    assert_ne!(
        inner.fmt_compact().to_string(),
        inner.to_string(),
        "the decode error has more than one layer, and the message shows all of them"
    );
}

#[test]
fn from_str_rejects_non_bech32() {
    assert!(matches!(
        InviteCode::from_str("definitely not bech32"),
        Err(InviteCodeParseError::Bech32(_))
    ));
}

#[test]
fn from_str_reports_corrupt_prefixed_base32() {
    use crate::util::FmtCompact as _;

    let err = InviteCode::from_str(&format!("{FEDIMINT_PREFIX}not!base32"))
        .expect_err("not!base32 is not valid base32");
    assert!(matches!(err, InviteCodeParseError::Base32(_)), "{err:?}");
    assert_eq!(err.fmt_compact().to_string(), err.to_string());
}

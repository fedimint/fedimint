use std::collections::BTreeMap;

use thiserror::Error;

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;
use crate::util::FmtCompact as _;

/// Lowercase RFC 4648 Base32hex alphabet (32 characters).
const RFC4648: [u8; 32] = *b"0123456789abcdefghijklmnopqrstuv";

/// Prefix used for some of the user-facing Base32 encodings in Fedimint to
/// allow easy identification
pub const FEDIMINT_PREFIX: &str = "fedimint";

/// Encodes the input bytes as Base32 (hex variant) using lowercase characters
pub fn encode(input: &[u8]) -> String {
    let mut output = Vec::with_capacity(((8 * input.len()) / 5) + 1);

    let mut buffer = 0;
    let mut bits = 0;

    for byte in input {
        buffer |= (*byte as usize) << bits;
        bits += 8;

        while bits >= 5 {
            output.push(RFC4648[buffer & 0b11111]);

            buffer >>= 5;
            bits -= 5;
        }
    }

    if bits > 0 {
        output.push(RFC4648[buffer & 0b11111]);
    }

    String::from_utf8(output).unwrap()
}

/// Decodes a base 32 string back to raw bytes. Returns an error
/// if any invalid character is encountered.
pub fn decode(input: &str) -> Result<Vec<u8>, Base32DecodeError> {
    let decode_table = RFC4648
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, i))
        .collect::<BTreeMap<u8, usize>>();

    let mut output = Vec::with_capacity(((5 * input.len()) / 8) + 1);

    let mut buffer = 0;
    let mut bits = 0;

    for (index, ch) in input.char_indices() {
        let value = ch
            .is_ascii()
            .then(|| decode_table.get(&(ch as u8)).copied())
            .flatten()
            .ok_or(Base32DecodeError::InvalidCharacter { ch, index })?;

        buffer |= value << bits;
        bits += 5;

        while bits >= 8 {
            output.push((buffer & 0xFF) as u8);

            buffer >>= 8;
            bits -= 8;
        }
    }

    Ok(output)
}

pub fn encode_prefixed<T: Encodable>(prefix: &str, encodable: &T) -> String {
    encode_prefixed_bytes(prefix, &encodable.consensus_encode_to_vec())
}

pub fn encode_prefixed_bytes(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}{}", encode(bytes))
}

pub fn decode_prefixed<T: Decodable>(prefix: &str, s: &str) -> Result<T, PrefixedDecodeError> {
    Ok(T::consensus_decode_whole(
        &decode_prefixed_bytes(prefix, s)?,
        &ModuleDecoderRegistry::default(),
    )?)
}

pub fn decode_prefixed_bytes(prefix: &str, s: &str) -> Result<Vec<u8>, PrefixedDecodeError> {
    let s = s.to_lowercase();
    if !s.starts_with(prefix) {
        return Err(PrefixedDecodeError::InvalidPrefix {
            expected: prefix.to_owned(),
        });
    }
    Ok(decode(&s[prefix.len()..])?)
}

/// Failure to decode a raw base 32 string.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Base32DecodeError {
    /// A character outside the RFC 4648 base32hex alphabet was encountered.
    ///
    /// `index` is a byte offset into the string passed to [`decode`]. When the
    /// error originates in [`decode_prefixed`] or [`decode_prefixed_bytes`],
    /// that string is the payload after the prefix was stripped and the input
    /// was lowercased, not the string the caller supplied.
    #[error("Invalid base32 character {ch:?} at byte index {index}")]
    InvalidCharacter { ch: char, index: usize },
}

/// Failure to decode a prefixed base 32 string into a value.
///
/// The byte offset in a [`Base32DecodeError::InvalidCharacter`] source refers
/// to the payload after the prefix was stripped and the input was lowercased,
/// not to the string the caller supplied.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PrefixedDecodeError {
    /// The string does not start with the expected prefix.
    #[error("Invalid prefix, expected '{expected}'")]
    InvalidPrefix { expected: String },
    /// The payload is not valid base 32.
    #[error("Invalid base32 payload: {0}")]
    Base32Decode(Base32DecodeError),
    /// The decoded bytes are not a valid consensus encoding of the target type.
    #[error("Invalid consensus encoding in base32 payload: {}", .0.fmt_compact())]
    ConsensusDecode(DecodeError),
}

impl From<DecodeError> for PrefixedDecodeError {
    fn from(source: DecodeError) -> Self {
        Self::ConsensusDecode(source)
    }
}

impl From<Base32DecodeError> for PrefixedDecodeError {
    fn from(source: Base32DecodeError) -> Self {
        Self::Base32Decode(source)
    }
}

#[test]
fn test_base_32_roundtrip() {
    const TEST_PREFIX: &str = "test";
    let data: [u8; 10] = [0x50, 0xAB, 0x3F, 0x77, 0x01, 0xCD, 0x55, 0xFE, 0x10, 0x99];

    for n in 1..10 {
        let bytes = data[0..n].to_vec();

        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);

        assert_eq!(
            decode_prefixed::<Vec<u8>>(TEST_PREFIX, &encode_prefixed(TEST_PREFIX, &bytes)).unwrap(),
            bytes
        );

        assert_eq!(
            decode_prefixed::<Vec<u8>>(
                TEST_PREFIX,
                &encode_prefixed(TEST_PREFIX, &bytes).to_ascii_uppercase()
            )
            .unwrap(),
            bytes
        );
    }
}

#[test]
fn decode_reports_invalid_character_position() {
    assert_eq!(
        decode("ab!c"),
        Err(Base32DecodeError::InvalidCharacter { ch: '!', index: 2 })
    );
}

#[test]
fn decode_escapes_invalid_character_in_message() {
    let err = decode("a\nb").expect_err("a newline is not in the base32 alphabet");

    assert_eq!(
        err,
        Base32DecodeError::InvalidCharacter { ch: '\n', index: 1 }
    );
    assert_eq!(
        err.to_string(),
        "Invalid base32 character '\\n' at byte index 1"
    );
}

#[test]
fn decode_prefixed_bytes_rejects_wrong_prefix() {
    assert!(matches!(
        decode_prefixed_bytes("fed", "xyz00"),
        Err(PrefixedDecodeError::InvalidPrefix { expected }) if expected == "fed"
    ));
}

#[test]
fn decode_prefixed_reports_the_whole_decode_chain() {
    use std::str::FromStr;

    use crate::encoding::Encodable;
    use crate::invite_code::InviteCode;
    use crate::util::FmtCompact as _;

    // Dropping the last byte of a valid invite code cuts off mid-federation-id, so
    // the reader runs out of input partway through the consensus decode instead of
    // failing on the very first byte.
    let invite_code_str = "fed11qgqpu8rhwden5te0vejkg6tdd9h8gepwd4cxcumxv4jzuen0duhsqqfqh6nl7sgk72caxfx8khtfnn8y436q3nhyrkev3qp8ugdhdllnh86qmp42pm";
    let invite = InviteCode::from_str(invite_code_str).expect("valid invite code");
    let bytes = invite.consensus_encode_to_vec();
    let encoded = encode_prefixed_bytes(FEDIMINT_PREFIX, &bytes[..bytes.len() - 1]);

    let err =
        decode_prefixed::<InviteCode>(FEDIMINT_PREFIX, &encoded).expect_err("payload is truncated");
    let text = err.to_string();
    let err_fmt_compact = err.fmt_compact().to_string();
    let PrefixedDecodeError::ConsensusDecode(inner) = err else {
        panic!("a truncated payload is a decode error: {err:?}");
    };

    assert_eq!(
        text,
        format!(
            "Invalid consensus encoding in base32 payload: {}",
            inner.fmt_compact()
        )
    );
    assert_ne!(inner.fmt_compact().to_string(), inner.to_string());
    assert_eq!(
        err_fmt_compact, text,
        "no source, so nothing is printed twice"
    );
}

use std::collections::BTreeMap;

use anyhow::{Context, ensure};

use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

/// Lowercase RFC 4648 Base32hex alphabet (32 characters).
const RFC4648: [u8; 32] = *b"0123456789abcdefghijklmnopqrstuv";

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
pub fn decode(input: &str) -> anyhow::Result<Vec<u8>> {
    let decode_table = RFC4648
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, i))
        .collect::<BTreeMap<u8, usize>>();

    let mut output = Vec::with_capacity(((5 * input.len()) / 8) + 1);

    let mut buffer = 0;
    let mut bits = 0;

    for byte in input.as_bytes() {
        let value = decode_table
            .get(byte)
            .copied()
            .context("Invalid character encountered")?;

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

pub fn encode_oob<T: Encodable>(encodable: &T) -> String {
    format!("fedimint{}", encode(&encodable.consensus_encode_to_vec()))
}

pub fn decode_oob<T: Decodable>(s: &str) -> anyhow::Result<T> {
    let s = s.to_lowercase();

    ensure!(s.starts_with("fedimint"), "Invalid Prefix");

    Ok(T::consensus_decode_whole(
        &decode(&s[8..])?,
        &ModuleDecoderRegistry::default(),
    )?)
}

#[test]
fn test_base_32_roundtrip() {
    let data: [u8; 10] = [0x50, 0xAB, 0x3F, 0x77, 0x01, 0xCD, 0x55, 0xFE, 0x10, 0x99];

    for n in 1..10 {
        let bytes = data[0..n].to_vec();

        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);

        assert_eq!(decode_oob::<Vec<u8>>(&encode_oob(&bytes)).unwrap(), bytes);

        assert_eq!(
            decode_oob::<Vec<u8>>(&encode_oob(&bytes).to_ascii_uppercase()).unwrap(),
            bytes
        );
    }
}

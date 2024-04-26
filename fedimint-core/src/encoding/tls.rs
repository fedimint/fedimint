use std::io::{Error, Write};

use hex::ToHex;
use tokio_rustls::rustls;

use crate::encoding::Encodable;

impl Encodable for rustls::Certificate {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.encode_hex::<String>().consensus_encode(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockCertificate(Vec<u8>);

    impl MockCertificate {
        fn new(data: Vec<u8>) -> Self {
            MockCertificate(data)
        }
    }

    impl Encodable for MockCertificate {
        fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
            self.0.encode_hex::<String>().consensus_encode(writer)
        }
    }

    /// Test the `consensus_encode` method for `rustls::Certificate`.
    /// This method encodes a certificate into a consensus format.
    #[test]
    fn test_consensus_encode() {
        let test_cases = [
            (vec![0x12, 0x34, 0x56, 0x78], "\u{8}12345678"),
            (vec![0xAB, 0xCD, 0xEF], "\u{6}abcdef"),
            (vec![0xFF], "\u{2}ff"),
            (vec![], "\0"),
            (vec![0x00, 0x01, 0x02, 0x03, 0x04], "\n0001020304"),
        ];
    
        for (data, expected_output) in &test_cases {
            let certificate = MockCertificate::new(data.clone());
    
            let mut output_buffer = Cursor::new(Vec::new());
            let result = certificate.consensus_encode(&mut output_buffer);
    
            assert!(result.is_ok());
    
            let encoded_data = String::from_utf8(output_buffer.into_inner()).unwrap();
            assert_eq!(encoded_data, *expected_output);
        }
    }
    
}

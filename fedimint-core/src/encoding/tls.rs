use std::io::{Error, Write};

use hex::ToHex;

use crate::encoding::Encodable;

impl Encodable for tokio_rustls::rustls::Certificate {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.0.encode_hex::<String>().consensus_encode(writer)
    }
}

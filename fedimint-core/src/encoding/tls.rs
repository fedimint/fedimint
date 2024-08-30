use std::io::{Error, Write};

use hex::ToHex;
use tokio_rustls::rustls;

use crate::encoding::Encodable;

impl Encodable for rustls::pki_types::CertificateDer<'_> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.encode_hex::<String>().consensus_encode(writer)
    }
}

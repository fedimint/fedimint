use std::num::ParseIntError;

use bitcoin_hashes::hex::FromHex;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::PeerId;

pub fn from_hex<D: Decodable>(s: &str) -> Result<D, anyhow::Error> {
    let bytes = Vec::from_hex(s)?;
    Ok(D::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}

pub fn parse_peer_id(s: &str) -> Result<PeerId, ParseIntError> {
    Ok(PeerId::from(s.parse::<u16>()?))
}

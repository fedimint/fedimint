use std::num::ParseIntError;

use fedimint_core::PeerId;

pub fn parse_peer_id(s: &str) -> Result<PeerId, ParseIntError> {
    Ok(PeerId::from(s.parse::<u16>()?))
}

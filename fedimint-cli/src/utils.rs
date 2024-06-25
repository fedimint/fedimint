use std::num::ParseIntError;

use fedimint_api_client::api::net::Connector;
use fedimint_core::PeerId;

pub fn parse_peer_id(s: &str) -> Result<PeerId, ParseIntError> {
    Ok(PeerId::from(s.parse::<u16>()?))
}

pub fn parse_connector(s: &str) -> Result<Connector, &'static str> {
    s.parse::<Connector>()
}

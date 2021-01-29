use crate::net::framed::Framed;
use crate::HoneyBadgerMessage;
use hbbft::crypto::PublicKey;
use tokio::net::TcpStream;
use tokio_util::compat::Compat;

pub struct Peer {
    pub id: u16,
    pub conn: Framed<Compat<TcpStream>, HoneyBadgerMessage>,
    pub hbbft_pub_key: PublicKey,
}

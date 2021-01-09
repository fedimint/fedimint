use hbbft::crypto::PublicKey;
use tokio::net::TcpStream;

pub struct Peer {
    pub id: u16,
    pub conn: TcpStream,
    pub pubkey: PublicKey,
}

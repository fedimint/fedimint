use bitcoin_hashes::{sha256, Hash as BitcoinHash, Hmac, HmacEngine};
use secp256k1::{Secp256k1, Verification};

/// An object that can be used as a ricardian contract to tweak a key
pub trait Contract {
    /// Serialize the contract in a deterministic way to be used as a tweak
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

/// A key or object containing keys that may be tweaked for pay-to-contract constructions
pub trait Tweakable {
    /// Tweak the key with a `tweak` contract
    fn tweak<Ctx: Verification, Ctr: Contract>(&self, tweak: &Ctr, secp: &Secp256k1<Ctx>) -> Self;
}

impl Tweakable for secp256k1::PublicKey {
    fn tweak<Ctx: Verification, Ctr: Contract>(&self, tweak: &Ctr, secp: &Secp256k1<Ctx>) -> Self {
        let mut hasher = HmacEngine::<sha256::Hash>::new(&self.serialize()[..]);
        tweak.encode(&mut hasher).expect("hashing is infallible");
        let tweak = Hmac::from_engine(hasher).into_inner();

        let mut key = *self;
        key.add_exp_assign(secp, &tweak[..])
            .expect("tweak is always 32 bytes, other failure modes are negligible");

        key
    }
}

impl Contract for secp256k1::PublicKey {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.serialize())
    }
}

impl Contract for Vec<u8> {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self)
    }
}

impl Contract for musig::PubKey {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes()[..])
    }
}

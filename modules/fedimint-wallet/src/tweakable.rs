use std::io::Write;

use bitcoin::hashes::{sha256, Hash as BitcoinHash, Hmac, HmacEngine};
use secp256k1::{Scalar, Secp256k1, Signing, Verification};

/// An object that can be used as a Ricardian contract to tweak a key
pub trait Contract {
    /// Serialize the contract in a deterministic way to be used as a tweak
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

/// A key or object containing keys that may be tweaked for pay-to-contract
/// constructions
pub trait Tweakable {
    /// Tweak the key with a `tweak` contract
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self;
}

impl Tweakable for secp256k1::PublicKey {
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self {
        let mut hasher = HmacEngine::<sha256::Hash>::new(&self.serialize()[..]);
        tweak.encode(&mut hasher).expect("hashing is infallible");
        let tweak = Hmac::from_engine(hasher).into_inner();

        self.add_exp_tweak(secp, &Scalar::from_be_bytes(tweak).expect("can't fail"))
            .expect("tweak is always 32 bytes, other failure modes are negligible")
    }
}

impl Tweakable for secp256k1::SecretKey {
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak_in: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self {
        let pub_key = secp256k1::PublicKey::from_secret_key(secp, self);

        let tweak = {
            let mut hasher = HmacEngine::<sha256::Hash>::new(&pub_key.serialize()[..]);
            tweak_in.encode(&mut hasher).expect("hashing is infallible");
            Hmac::from_engine(hasher).into_inner()
        };

        self.add_tweak(&Scalar::from_be_bytes(tweak).expect("can't fail"))
            .expect("Tweaking priv key failed") // TODO: why could this happen?
    }
}

impl Contract for secp256k1::PublicKey {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.serialize())
    }
}

impl Contract for Vec<u8> {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

impl Contract for [u8; 32] {
    fn encode<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

impl Contract for secp256k1::XOnlyPublicKey {
    fn encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.serialize()[..])
    }
}

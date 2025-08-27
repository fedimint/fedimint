use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, PublicKey};
use fedimint_core::secp256k1::ecdh;
use rand;

pub fn generate(static_pk: PublicKey) -> ([u8; 32], PublicKey) {
    let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let tweak = ecdh::SharedSecret::new(&static_pk, &keypair.secret_key());

    (tweak.secret_bytes(), keypair.public_key())
}

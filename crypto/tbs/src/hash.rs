use group::Group;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha3::digest::generic_array::typenum::U32;
use sha3::Digest;

const HASH_TAG: &[u8] = b"TBS_BLS12-381_";

pub fn hash_bytes_to_curve<G: Group>(data: &[u8]) -> G {
    let mut hash_engine = sha3::Sha3_256::new();
    hash_engine.update(HASH_TAG);
    hash_engine.update(data);
    hash_to_curve(hash_engine)
}

/// **IMPORTANT**: the byte hashing fn includes a tag, this doesn't
pub fn hash_to_curve<G: Group, H: Digest<OutputSize = U32>>(hash: H) -> G {
    let mut prng = ChaChaRng::from_seed(hash.finalize().into());
    G::random(&mut prng)
}

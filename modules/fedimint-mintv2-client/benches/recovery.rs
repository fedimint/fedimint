use fedimint_core::encoding::Encodable;
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_client::issuance::{self};

fn main() {
    divan::main();
}

#[divan::bench]
fn grind_tweak(bencher: divan::Bencher) {
    let root_secret = DerivableSecret::new_root(&[0u8; 32], &[0u8; 8]);

    bencher.bench(|| issuance::grind_tweak(&root_secret));
}

#[divan::bench]
fn check_tweak(bencher: divan::Bencher) {
    let root_secret = DerivableSecret::new_root(&[0u8; 32], &[0u8; 8]);
    let seed = root_secret.to_random_bytes::<32>();
    let tweak = [0u8; 12];

    bencher.bench(|| issuance::check_tweak(tweak, seed));
}

#[divan::bench]
fn check_nonce(bencher: divan::Bencher) {
    let root_secret = DerivableSecret::new_root(&[0u8; 32], &[0u8; 8]);
    let tweak = issuance::grind_tweak(&root_secret);
    let nonce_hash = issuance::nonce(tweak, &root_secret).consensus_hash();

    bencher.bench(|| issuance::check_nonce(tweak, &root_secret, nonce_hash));
}

use std::hint::black_box;

use bls12_381::{G2Affine, G2Projective};
use criterion::{Criterion, criterion_group, criterion_main};
use fedimint_core::encoding::Decodable;
use fedimint_mint_client::{SpendableNote, SpendableNoteUndecoded};
use threshold_crypto::group::Group as _;

fn bench_note_decoding(c: &mut Criterion) {
    const NOTE_HEX: &str = "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd";

    let mut group = c.benchmark_group("SpendableNote decoding");

    group.bench_function("SpendableNote", |b| {
        b.iter(|| {
            SpendableNote::consensus_decode_hex(black_box(NOTE_HEX), &Default::default()).unwrap()
        })
    });
    group.bench_function("SpendableNoteUndecoded", |b| {
        b.iter(|| {
            SpendableNoteUndecoded::consensus_decode_hex(black_box(NOTE_HEX), &Default::default())
                .unwrap()
        })
    });
}

fn bench_g2_decoding(c: &mut Criterion) {
    let g2 = G2Projective::random(rand::thread_rng());
    let g2 = G2Affine::from(g2);

    let compressed = g2.to_compressed();
    let uncompressed = g2.to_uncompressed();

    let mut group = c.benchmark_group("G2Affine decoding");

    group.bench_function("G2Affine from uncompressed", |b| {
        b.iter(|| G2Affine::from_uncompressed(&black_box(uncompressed)).unwrap())
    });
    group.bench_function("G2Affine from compressed", |b| {
        b.iter(|| G2Affine::from_compressed(&black_box(compressed)).unwrap())
    });
}
criterion_group!(benches, bench_note_decoding, bench_g2_decoding);
criterion_main!(benches);

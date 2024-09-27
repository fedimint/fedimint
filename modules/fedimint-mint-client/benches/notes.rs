use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use fedimint_core::encoding::Decodable;
use fedimint_mint_client::{SpendableNote, SpendableNoteUndecoded};

fn bench_note_decoding(c: &mut Criterion) {
    const NOTE_HEX : &str = "a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd";

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

criterion_group!(benches, bench_note_decoding);
criterion_main!(benches);

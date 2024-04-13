use divan::black_box;
use fedimint_core::encoding::Decodable;
use fedimint_mint_client::{SpendableNote, SpendableNoteUndecoded};

fn main() {
    // Run registered benchmarks.
    divan::main();
}

#[divan::bench]
fn spendable_note_decode() -> SpendableNote {
    SpendableNote::consensus_decode_hex(black_box("a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd"), &Default::default()).unwrap()
}

#[divan::bench]
fn spendable_note_undecoded_decode() -> SpendableNoteUndecoded {
    SpendableNoteUndecoded::consensus_decode_hex(black_box("a5dd3ebacad1bc48bd8718eed5a8da1d68f91323bef2848ac4fa2e6f8eed710f3178fd4aef047cc234e6b1127086f33cc408b39818781d9521475360de6b205f3328e490a6d99d5e2553a4553207c8bd"), &Default::default()).unwrap()
}

use fedimint_core::epoch::ConsensusItem;
use fedimint_fuzz::all_standard_modules;
use honggfuzz::fuzz;

fn main() {
    let decoders = all_standard_modules();

    loop {
        fuzz!(|data| {
            fedimint_fuzz::test_decodable_with_decoders_vs_defaults::<ConsensusItem>(
                data, &decoders,
            )
        });
    }
}

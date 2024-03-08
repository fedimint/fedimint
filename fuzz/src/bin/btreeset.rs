use std::collections::BTreeSet;

use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<BTreeSet<u8>>(data) });
    }
}

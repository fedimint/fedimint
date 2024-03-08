use std::collections::BTreeMap;

use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<BTreeMap<u8, u8>>(data) });
    }
}

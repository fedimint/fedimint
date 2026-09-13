use std::time::Duration;

use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<Duration>(data) });
    }
}

use std::collections::VecDeque;

use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<VecDeque<u16>>(data) });
    }
}

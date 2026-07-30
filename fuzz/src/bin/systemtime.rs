use std::time::SystemTime;

use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<SystemTime>(data) });
    }
}

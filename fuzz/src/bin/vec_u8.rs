use honggfuzz::fuzz;

fn main() {
    loop {
        // decoding of Vec<u8> is special cased so gets its own fuzzing target
        fuzz!(|data| { fedimint_fuzz::test_decodable::<Vec<u8>>(data) });
    }
}

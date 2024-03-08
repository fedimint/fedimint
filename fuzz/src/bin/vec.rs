use honggfuzz::fuzz;

fn main() {
    loop {
        // Using Vec<u16>, as Vec<u8> is special-cased and tested separtely
        fuzz!(|data| { fedimint_fuzz::test_decodable::<Vec<u16>>(data) });
    }
}

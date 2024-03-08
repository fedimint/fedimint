use fedimint_core::session_outcome::SessionOutcome;
use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data| { fedimint_fuzz::test_decodable::<SessionOutcome>(data) });
    }
}

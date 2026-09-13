use fedimint_core::backup::ClientBackupSnapshot;
use honggfuzz::fuzz;

fn main() {
    loop {
        // its first encoded field is the legacy timestamp, so this reaches
        // decode_legacy_system_time_from_finite_reader on the first bytes
        fuzz!(|data| { fedimint_fuzz::test_decodable::<ClientBackupSnapshot>(data) });
    }
}

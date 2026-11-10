use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleRegistry;

use super::{test_decodable, test_decodable_with_decoders_vs_defaults};

#[test]
fn partial_decode_limit_tracks_consumed_bytes() {
    let mut data = (fedimint_core::encoding::MAX_DECODE_SIZE as u64).consensus_encode_to_vec();
    data.resize(data.len() + fedimint_core::encoding::MAX_DECODE_SIZE, 0);
    assert!(
        Vec::<u8>::consensus_decode_partial(&mut data.as_slice(), &ModuleRegistry::default())
            .is_err()
    );

    data.resize(fedimint_core::encoding::MAX_DECODE_SIZE + 1, 0);
    data.fill(0);
    test_decodable::<Vec<u8>>(&data);
    test_decodable_with_decoders_vs_defaults::<Vec<u8>>(&data, &ModuleRegistry::default());
}

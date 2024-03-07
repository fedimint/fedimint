use fedimint_core::encoding::{Decodable, Encodable};

pub fn test_decodable<T>(data: &[u8])
where
    T: Decodable + Encodable,
{
    if let Ok(v) = T::consensus_decode(&mut &data[..], &Default::default()) {
        let encoded_vec = v.consensus_encode_to_vec();
        // helps debugging to have it standalone
        let encoded = encoded_vec.as_slice();

        assert_eq!(&data[..encoded.len()], encoded);
    }
}

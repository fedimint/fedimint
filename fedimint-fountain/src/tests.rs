use super::{FountainDecoder, FountainEncoder};

#[test]
fn test_fountain_encode_decode() {
    for n in 0..10000 {
        test_fountain_encode_decode_for_n(n);
    }
}

fn test_fountain_encode_decode_for_n(n: usize) {
    let original = (0..n).map(|i| i as u8).collect::<Vec<u8>>();

    let mut encoder = FountainEncoder::new(&original, 1000);

    let mut decoder: FountainDecoder<Vec<u8>> = FountainDecoder::default();

    for k in 0..30 {
        let fragment = encoder.next_fragment();

        if let Some(data) = decoder.add_fragment(&fragment) {
            assert_eq!(data, original);
            if n.is_multiple_of(100) {
                println!("Decoded {} bytes within {} fragments", n, k + 1);
            }
            return;
        }

        assert!(
            decoder.add_fragment(&fragment).is_none(),
            "Should not decode yet"
        );

        let _ = encoder.next_fragment();
    }

    panic!("Decoder did not decode the original data within 25 fragments");
}

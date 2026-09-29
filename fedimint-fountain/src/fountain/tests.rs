use assert_matches::assert_matches;

use super::{Decoder, Encoder, EncodingMetadata, Error, Fragment, fragment_length};

#[test]
fn test_fragment_length() {
    assert_eq!(fragment_length(12345, 1955), 1764);
    assert_eq!(fragment_length(12345, 30000), 12345);

    assert_eq!(fragment_length(10, 4), 4);
    assert_eq!(fragment_length(10, 5), 5);
    assert_eq!(fragment_length(10, 6), 5);
    assert_eq!(fragment_length(10, 10), 10);
}

#[test]
#[should_panic(expected = "assertion failed")]
fn test_fountain_encoder_zero_max_length() {
    Encoder::new(b"foo", 0);
}

#[test]
#[should_panic(expected = "assertion failed")]
fn test_empty_encoder() {
    Encoder::new(&[], 1);
}

#[test]
fn test_decoder_fragment_validation() {
    let mut encoder1 = Encoder::new(b"foo", 2);
    let mut encoder2 = Encoder::new(b"bar", 2);
    let mut decoder = Decoder::default();

    // Receive first fragment from encoder1 - not complete yet
    assert_eq!(decoder.receive(encoder1.next_fragment()).unwrap(), None);

    // Try to receive fragment from encoder2 with different metadata - should reject
    assert_matches!(
        decoder.receive(encoder2.next_fragment()),
        Err(Error::InconsistentFragment)
    );

    // Receiving another fragment from encoder1 should work and complete
    assert_eq!(
        decoder.receive(encoder1.next_fragment()).unwrap(),
        Some(b"foo".to_vec())
    );
}

#[test]
fn test_empty_decoder_empty_fragment() {
    let mut decoder = Decoder::default();
    let mut fragment = Fragment {
        meta: EncodingMetadata::new(8, 100, [0x12, 0x34, 0x56, 0x78]),
        index: 12,
        data: vec![1, 5, 3, 3, 5],
    };

    // Check simple_fragments.
    fragment.meta.simple_fragments = 0;
    assert_matches!(
        decoder.receive(fragment.clone()),
        Err(Error::InvalidFragment)
    );
    fragment.meta.simple_fragments = 8;

    // Check message_length.
    fragment.meta.message_length = 0;
    assert_matches!(
        decoder.receive(fragment.clone()),
        Err(Error::InvalidFragment)
    );
    fragment.meta.message_length = 100;

    // Check data.
    fragment.data = vec![];
    assert_matches!(
        decoder.receive(fragment.clone()),
        Err(Error::InvalidFragment)
    );
}

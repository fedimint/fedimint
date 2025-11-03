//! Fountain encoder/decoder for splitting and recombining byte payloads
//!
//! This is an inline fork of the fountain module from ur-rs,
//! providing rateless fountain codes for efficient data transmission.
//!
//! The fountain encoder splits a byte payload into multiple segments
//! and emits an unbounded stream of parts which can be recombined at
//! the receiving decoder side. The emitted parts are either original
//! payload segments, or constructed by xor-ing a certain set of payload
//! segments.

mod fountain;

use std::marker::PhantomData;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;

pub struct FountainEncoder {
    encoder: fountain::Encoder,
}

impl FountainEncoder {
    pub fn new(encodable: impl Encodable, max_fragment_length: usize) -> Self {
        Self {
            encoder: fountain::Encoder::new(
                encodable.consensus_encode_to_vec().as_slice(),
                max_fragment_length,
            ),
        }
    }

    /// Fragments never repeat, so this can be called indefinitely
    pub fn next_fragment(&mut self) -> fountain::Fragment {
        self.encoder.next_fragment()
    }
}

/// Decoder for fountain-encoded encodable types
pub struct FountainDecoder<E: Decodable> {
    decoder: fountain::Decoder,
    _pd: PhantomData<E>,
}

impl<E: Decodable> Default for FountainDecoder<E> {
    fn default() -> Self {
        Self {
            decoder: fountain::Decoder::default(),
            _pd: PhantomData,
        }
    }
}

impl<E: Decodable> FountainDecoder<E> {
    /// Add a scanned fragment. Returns Some(E) when decoding is complete
    pub fn add_fragment(&mut self, fragment: &fountain::Fragment) -> Option<E> {
        // Try to receive the fragment
        match self.decoder.receive(fragment.clone()) {
            Ok(Some(bytes)) => {
                // Decoding complete!
                Decodable::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default()).ok()
            }
            Ok(None) => {
                // Not done yet
                None
            }
            Err(_) => {
                // Invalid fragment, reset decoder
                self.decoder = fountain::Decoder::default();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                if n % 100 == 0 {
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
}

use std::collections::BTreeMap;

use bitcoin_hashes::Hash;
use fedimint_core::encoding::{Decodable, Encodable};
use rand::distributions::{Distribution, WeightedIndex};
use rand::seq::IteratorRandom;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

fn checksum(data: &[u8]) -> [u8; 4] {
    bitcoin_hashes::sha256::Hash::hash(data).to_byte_array()[..4]
        .try_into()
        .unwrap()
}

#[derive(Debug)]
pub enum Error {
    /// Received fragment is invalid.
    InvalidFragment,
    /// Received fragment is inconsistent with previous ones.
    InconsistentFragment,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFragment => write!(f, "received invalid fragment"),
            Self::InconsistentFragment => write!(f, "fragment is inconsistent with previous ones"),
        }
    }
}

/// An encoder capable of emitting fountain-encoded transmissions.
#[derive(Debug)]
pub struct Encoder {
    fragments: Vec<Vec<u8>>,
    message_length: usize,
    checksum: [u8; 4],
    index: u32,
}

impl Encoder {
    pub fn new(message: &[u8], max_fragment_length: usize) -> Self {
        assert!(!message.is_empty());
        assert!(max_fragment_length > 0);

        let fragment_length = fragment_length(message.len(), max_fragment_length);

        let fragments = partition(message.to_vec(), fragment_length);

        Self {
            fragments,
            message_length: message.len(),
            checksum: checksum(message),
            index: 0,
        }
    }

    /// Returns the next fragment to be emitted by the fountain encoder.
    /// After all fragments of the original message have been emitted once,
    /// the fountain encoder will emit the result of xoring together the
    /// fragments selected by the Xoshiro RNG (which could be a single
    /// fragment).
    pub fn next_fragment(&mut self) -> Fragment {
        let index = self.index;

        self.index += 1;

        let indexes = choose_fragments(self.fragments.len(), self.checksum, index);

        let mut data = vec![0; self.fragments[0].len()];

        for item in indexes {
            xor(&mut data, &self.fragments[item]);
        }

        Fragment {
            meta: EncodingMetadata::new(self.fragments.len(), self.message_length, self.checksum),
            index,
            data,
        }
    }
}

pub const fn fragment_length(data_length: usize, max_fragment_length: usize) -> usize {
    data_length.div_ceil(data_length.div_ceil(max_fragment_length))
}

pub fn partition(mut data: Vec<u8>, fragment_length: usize) -> Vec<Vec<u8>> {
    let mut padding = vec![0; (fragment_length - (data.len() % fragment_length)) % fragment_length];

    data.append(&mut padding);

    data.chunks(fragment_length).map(<[u8]>::to_vec).collect()
}

fn choose_fragments(fragment_count: usize, checksum: [u8; 4], index: u32) -> Vec<usize> {
    if (index as usize) < fragment_count {
        return vec![index as usize];
    }

    let seed = (checksum, index).consensus_hash_sha256();

    let mut rng = ChaCha20Rng::from_seed(seed.to_byte_array());

    // Sample degree from Ideal Soliton Distribution: P(degree = k) ∝ 1/k
    let degree = WeightedIndex::new((0..fragment_count).map(|x| 1.0 / (x + 1) as f64))
        .unwrap()
        .sample(&mut rng)
        + 1;

    // Choose degree random fragments
    (0..fragment_count).choose_multiple(&mut rng, degree)
}

fn xor(v1: &mut [u8], v2: &[u8]) {
    assert_eq!(v1.len(), v2.len());

    for (x1, &x2) in v1.iter_mut().zip(v2.iter()) {
        *x1 ^= x2;
    }
}

/// Encoding metadata for a fragment.
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct EncodingMetadata {
    simple_fragments: u32,
    message_length: u32,
    checksum: [u8; 4],
}

impl EncodingMetadata {
    pub fn new(simple_fragments: usize, message_length: usize, checksum: [u8; 4]) -> Self {
        Self {
            simple_fragments: simple_fragments as u32,
            message_length: message_length as u32,
            checksum,
        }
    }

    pub fn fragment_length(&self) -> usize {
        self.message_length().div_ceil(self.simple_fragments())
    }

    pub fn message_length(&self) -> usize {
        self.message_length as usize
    }

    pub fn checksum(&self) -> [u8; 4] {
        self.checksum
    }

    fn simple_fragments(&self) -> usize {
        self.simple_fragments as usize
    }

    fn verify(&self) -> bool {
        self.simple_fragments() > 0 && self.message_length() > 0 && self.fragment_length() > 0
    }
}

/// A fragment emitted by a fountain [`Encoder`].
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct Fragment {
    meta: EncodingMetadata,
    index: u32,
    data: Vec<u8>,
}

impl Fragment {
    /// Returns the indexes of the message segments that were combined.
    pub fn indexes(&self) -> Vec<usize> {
        choose_fragments(
            self.meta.simple_fragments(),
            self.meta.checksum(),
            self.index,
        )
    }
}

/// A decoder capable of receiving and recombining fountain-encoded
/// transmissions.
#[derive(Default)]
pub struct Decoder {
    decoded: BTreeMap<usize, Vec<u8>>,
    buffer: BTreeMap<Vec<usize>, Vec<u8>>,
    meta: Option<EncodingMetadata>,
}

impl Decoder {
    /// If the message is available, returns it, `None` otherwise.
    pub fn message(&self) -> Option<Vec<u8>> {
        if self.decoded.len() < self.meta.as_ref()?.simple_fragments() {
            return None;
        }

        let message = self
            .decoded
            .values()
            .flat_map(|data| data.clone())
            .take(self.meta.as_ref()?.message_length())
            .collect();

        Some(message)
    }

    /// Receives a fountain-encoded fragment into the decoder.
    pub fn receive(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, Error> {
        if let Some(message) = self.message() {
            return Ok(Some(message));
        }

        if !fragment.meta.verify() {
            return Err(Error::InvalidFragment);
        }

        if fragment.data.len() != fragment.meta.fragment_length() {
            return Err(Error::InvalidFragment);
        }

        match self.meta.as_ref() {
            None => {
                self.meta = Some(fragment.meta.clone());
            }
            Some(meta) => {
                if meta != &fragment.meta {
                    return Err(Error::InconsistentFragment);
                }
            }
        }

        if let [index] = fragment.indexes().as_slice() {
            self.process_simple(*index, fragment.data.clone());
        } else {
            self.process_complex(fragment.indexes(), fragment.data.clone());
        }

        Ok(self.message())
    }

    fn process_simple(&mut self, index: usize, data: Vec<u8>) {
        self.decoded.insert(index, data.clone());

        let mut queue = self.decoded.clone().into_iter().collect::<Vec<_>>();

        while let Some((index, simple)) = queue.pop() {
            for (mut indexes, mut data) in self
                .buffer
                .clone()
                .into_iter()
                .filter(|entry| entry.0.contains(&index))
            {
                self.buffer.remove(&indexes).unwrap();

                indexes.retain(|&i| i != index);

                xor(&mut data, &simple);

                if let [index] = indexes.as_slice() {
                    self.decoded.insert(*index, data.clone());
                    queue.push((*index, data));
                } else {
                    self.buffer.insert(indexes, data);
                }
            }
        }
    }

    fn process_complex(&mut self, mut indexes: Vec<usize>, mut data: Vec<u8>) {
        let to_remove: Vec<usize> = indexes
            .clone()
            .into_iter()
            .filter(|i| self.decoded.keys().any(|k| k == i))
            .collect();

        if indexes.len() == to_remove.len() {
            return;
        }

        for remove in &to_remove {
            xor(&mut data, self.decoded.get(remove).unwrap());
        }

        indexes.retain(|&i| !to_remove.contains(&i));

        if let [index] = indexes.as_slice() {
            self.decoded.insert(*index, data.clone());
        } else {
            self.buffer.insert(indexes, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(
            decoder.receive(encoder2.next_fragment()),
            Err(Error::InconsistentFragment)
        ));

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
        assert!(matches!(
            decoder.receive(fragment.clone()),
            Err(Error::InvalidFragment)
        ));
        fragment.meta.simple_fragments = 8;

        // Check message_length.
        fragment.meta.message_length = 0;
        assert!(matches!(
            decoder.receive(fragment.clone()),
            Err(Error::InvalidFragment)
        ));
        fragment.meta.message_length = 100;

        // Check data.
        fragment.data = vec![];
        assert!(matches!(
            decoder.receive(fragment.clone()),
            Err(Error::InvalidFragment)
        ));
    }
}

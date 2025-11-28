//! Merkle tree implementation for streaming data.
//!
//! This module provides a merkle tree implementation optimized for streaming
//! large datasets. It supports:
//!
//! - Computing merkle roots from async streams of items
//! - Generating chunk-based merkle proofs for efficient batch verification
//! - Verifying proofs that a chunk of leaves belongs to a merkle tree
//!
//! The tree is built using SHA-256 hashes and handles non-power-of-2 leaf
//! counts by padding with zero hashes.

use std::fmt;
use std::marker::PhantomData;

use bitcoin_hashes::{Hash, sha256};
use fedimint_core::encoding::{Decodable, Encodable};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

/// The root hash of a merkle tree, typed by the leaf element type `T`.
///
/// The root is computed as `Hash(num_leaves, inner_root)` where `inner_root`
/// is the standard merkle tree root.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleRoot<T>(
    #[serde(with = "::fedimint_core::encoding::as_hex")] pub sha256::Hash,
    #[serde(skip)] PhantomData<T>,
);

impl<T> MerkleRoot<T>
where
    T: Encodable,
{
    /// Computes the merkle root from an async stream of leaf items.
    ///
    /// The items are hashed using consensus encoding and combined into a
    /// binary merkle tree. If the number of items is not a power of 2,
    /// the tree is padded with zero hashes.
    pub async fn from_stream(stream: impl Stream<Item = T> + Unpin) -> Self {
        Self::from_stream_with_count(stream).await.0
    }

    /// Computes the merkle root from an async stream of leaf items and returns
    /// both the root and the number of leaves.
    pub async fn from_stream_with_count(stream: impl Stream<Item = T> + Unpin) -> (Self, u64) {
        let mut num_leaves: u64 = 0;

        let root_item = merkle_stream_post_order(stream)
            .map(|stack_item| {
                if stack_item.is_leaf() && !stack_item.is_padding() {
                    num_leaves += 1;
                }
                stack_item
            })
            .fold(None, |_acc, x| async move { Some(x) }) // get last item
            .await
            .expect("Root item is always yielded from the stream");

        let root_hash = (num_leaves, root_item.hash).consensus_hash_sha256();

        (Self(root_hash, PhantomData), num_leaves)
    }

    /// Verifies that a chunk merkle proof is valid against this root.
    ///
    /// Returns `true` if the proof is valid, meaning the chunk of leaves
    /// is authentically part of the merkle tree with this root.
    ///
    /// The verification process:
    /// 1. Computes the merkle root of just the chunk's leaves (padded to
    ///    `chunk_size` if needed)
    /// 2. Walks up the merkle path, combining with sibling hashes
    /// 3. Compares the final computed root with the expected root
    ///
    /// # Panics
    ///
    /// Panics if `chunk_size` exceeds `usize::MAX` (only possible on 32-bit
    /// platforms with very large chunk sizes).
    pub async fn verify_chunk_merkle_proof(
        &self,
        chunk_merkle_proof: &ChunkMerkleProof<T>,
    ) -> bool {
        // Validate chunk_size: must be non-zero and a power of 2
        if chunk_merkle_proof.chunk_size == 0 || !chunk_merkle_proof.chunk_size.is_power_of_two() {
            return false;
        }

        // If there's a merkle path OR the chunk is full, pad to chunk_size.
        // Otherwise, the chunk represents the entire tree which may be smaller
        // than chunk_size, so use natural padding (to nearest power of 2).
        let needs_chunk_padding = !chunk_merkle_proof.merkle_path.is_empty()
            || chunk_merkle_proof.chunk.len()
                == TryInto::<usize>::try_into(chunk_merkle_proof.chunk_size)
                    .expect("Would truncate");

        // Collect hashes first, then decide on padding length
        let chunk_hashes = chunk_merkle_proof
            .chunk
            .iter()
            .map(Encodable::consensus_hash_sha256);

        #[allow(clippy::cast_possible_truncation)] // chunk_size validated above
        let target_len = if needs_chunk_padding {
            chunk_merkle_proof.chunk_size as usize
        } else {
            chunk_merkle_proof.chunk.len()
        };

        let padded_stream = futures::stream::iter(chunk_hashes)
            .chain(futures::stream::repeat(sha256::Hash::all_zeros()))
            .take(target_len);

        let chunk_root = merkle_stream_post_order_hashes(padded_stream)
            .fold(None, |_acc, x| async move { Some(x) })
            .await
            .expect("The root is always yielded from the stream")
            .hash;

        let inner_root =
            chunk_merkle_proof
                .merkle_path
                .iter()
                .fold(chunk_root, |acc, merkle_path_item| {
                    if merkle_path_item.sibling_side == Side::Left {
                        (&merkle_path_item.sibling_hash, acc).consensus_hash_sha256()
                    } else {
                        (acc, &merkle_path_item.sibling_hash).consensus_hash_sha256()
                    }
                });

        let root = (&chunk_merkle_proof.num_leaves, &inner_root).consensus_hash_sha256();

        root == self.0
    }
}

impl<T> fmt::Display for MerkleRoot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> Encodable for MerkleRoot<T> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.consensus_encode(writer)?;
        Ok(())
    }
}

impl<T> Decodable for MerkleRoot<T> {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let hash = sha256::Hash::consensus_decode_partial(r, modules)?;
        Ok(MerkleRoot(hash, PhantomData))
    }
}

/// Internal state for generating chunk merkle proofs.
///
/// This struct stores the inner nodes of the merkle tree at and above the
/// chunk level, allowing efficient generation of merkle proofs for each chunk.
#[derive(Debug, Clone)]
struct ChunkMerkleProofStreamInner {
    /// Inner nodes at each level above the chunk level.
    /// `inner_nodes[0]` contains nodes at depth `chunk_log_2`,
    /// `inner_nodes[1]` at depth `chunk_log_2 + 1`, etc.
    inner_nodes: Vec<Vec<sha256::Hash>>,
    /// Total number of non-padding leaves in the tree.
    num_leaves: u64,
}

/// A merkle proof for a chunk of consecutive leaves.
///
/// This proof demonstrates that a contiguous sequence of leaves (`chunk`)
/// belongs to a merkle tree with a specific root. The proof consists of:
/// - The chunk itself (the leaves being proven)
/// - A merkle path from the chunk's subtree root to the overall tree root
/// - The total number of leaves for root verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMerkleProof<T> {
    /// Total number of non-padding leaves in the full tree.
    num_leaves: u64,
    /// The chunk size used when building the proof. Must be a power of 2.
    /// The last chunk may contain fewer items but is padded internally.
    chunk_size: u64,
    /// Path from the chunk's subtree root to the tree root.
    merkle_path: Vec<MerklePathItem>,
    /// The consecutive leaves that this proof covers.
    chunk: Vec<T>,
}

impl<T> ChunkMerkleProof<T> {
    /// Returns a reference to the chunk of leaves in this proof.
    pub fn chunk(&self) -> &Vec<T> {
        &self.chunk
    }

    /// Consumes the proof and returns the chunk of leaves.
    pub fn into_chunk(self) -> Vec<T> {
        self.chunk
    }
}

/// A single step in a merkle path from a leaf/subtree to the root.
///
/// Each item contains the hash of the sibling node and which side
/// that sibling is on, allowing reconstruction of the parent hash.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct MerklePathItem {
    /// Hash of the sibling node at this level.
    sibling_hash: sha256::Hash,
    /// Which side the sibling is on (determines hash order).
    sibling_side: Side,
}

/// Indicates which side a sibling node is on in a merkle path.
///
/// This determines the order of hashes when computing the parent:
/// - `Left`: `Hash(sibling, current)`
/// - `Right`: `Hash(current, sibling)`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
enum Side {
    /// Sibling is on the left, so it comes first in the hash.
    Left,
    /// Sibling is on the right, so it comes second in the hash.
    Right,
}

impl ChunkMerkleProofStreamInner {
    /// Creates a new chunk merkle proof generator by consuming the item stream.
    ///
    /// This traverses the entire stream once to build the internal node
    /// structure needed for generating proofs for any chunk.
    ///
    /// # Panics
    ///
    /// Panics if `chunk_size` is not a power of 2.
    pub async fn new<T, S>(item_stream: S, chunk_size: u64) -> Self
    where
        T: Encodable,
        S: Stream<Item = T> + Send + Unpin + 'static,
    {
        assert!(
            chunk_size.is_power_of_two(),
            "chunk_size must be a power of 2"
        );
        let chunk_log_2 = chunk_size.ilog2();

        let mut merkle_stream = merkle_stream_post_order(item_stream);
        let mut num_leaves = 0;

        let mut inner_nodes = Vec::<Vec<sha256::Hash>>::new();
        while let Some(stack_item) = merkle_stream.next().await {
            if stack_item.is_leaf() && !stack_item.is_padding() {
                num_leaves += 1;
            }
            if stack_item.depth >= chunk_log_2 {
                let inner_nodes_at_depth =
                    get_mut_or_insert(&mut inner_nodes, (stack_item.depth - chunk_log_2) as usize);
                inner_nodes_at_depth.push(stack_item.hash);
            }
        }

        // Remove the root, we don't need it for proof generation
        assert!(
            inner_nodes.pop().is_none_or(|x| x.len() == 1),
            "The root layer, if present, has exactly one element"
        );

        Self {
            inner_nodes,
            num_leaves,
        }
    }

    /// Returns the merkle path for the chunk at the given index.
    ///
    /// The path goes from the chunk's subtree root up to (but not including)
    /// the tree root, with each item containing the sibling hash needed
    /// to reconstruct the parent.
    fn get_merkle_path(&self, chunk_index: u64) -> Vec<MerklePathItem> {
        let chunk_index_shifted = (0..64).map(|i| (chunk_index >> i));
        self.inner_nodes
            .iter()
            .zip(chunk_index_shifted)
            .map(|(inner_nodes, chunk_index_shifted)| {
                // Our side is right if lsb is 1, left if lsb is 0
                let sibling_side = if chunk_index_shifted & 1 == 1 {
                    Side::Left
                } else {
                    Side::Right
                };
                // Flip lsb to get our sibling index
                let sibling_index: usize = (chunk_index_shifted ^ 1)
                    .try_into()
                    .expect("chunk_index_shifted is too large");
                let sibling_hash = inner_nodes[sibling_index];
                MerklePathItem {
                    sibling_hash,
                    sibling_side,
                }
            })
            .collect()
    }
}

/// Creates an async stream of chunk merkle proofs for the given items.
///
/// This function takes a stream generator (called twice: once to build the
/// tree structure, once to generate proofs) and produces a stream of
/// [`ChunkMerkleProof`]s, one for each chunk of `chunk_size` items.
///
/// # Arguments
///
/// * `item_stream_gen` - A function that produces the item stream. Called
///   twice, so the stream must be reproducible.
/// * `chunk_size` - Number of items per chunk. Must be a power of 2.
///
/// # Panics
///
/// Panics if `chunk_size` is not a power of 2.
pub async fn chunk_merkle_proof_stream<T, F, S>(
    item_stream_gen: F,
    chunk_size: u64,
) -> impl Stream<Item = ChunkMerkleProof<T>> + Send + Unpin
where
    T: Encodable + Send,
    F: Fn() -> S,
    S: Stream<Item = T> + Send + Unpin + 'static,
{
    let inner = ChunkMerkleProofStreamInner::new(item_stream_gen(), chunk_size).await;
    let mut item_stream = item_stream_gen()
        .chunks(chunk_size.try_into().expect("chunk_size is too large"))
        .enumerate();

    Box::pin(async_stream::stream! {
        while let Some((chunk_index, chunk)) = item_stream.next().await {
            let merkle_path = inner.get_merkle_path(chunk_index as u64);

            yield ChunkMerkleProof {
                num_leaves: inner.num_leaves,
                chunk_size,
                merkle_path,
                chunk,
            };
        }
    })
}

/// Iterates over the merkle tree nodes in post-order (leaves before parents).
///
/// This is the core algorithm for building the merkle tree from a stream.
/// It yields each node (both leaves and internal nodes) as they are computed,
/// allowing streaming computation of the tree without storing all leaves.
///
/// The algorithm uses a stack to track nodes at each depth. When two nodes
/// at the same depth are on the stack, they are combined into their parent.
/// Padding with zero hashes is added if the number of items is not a power of
/// 2.
///
/// # Returns
///
/// A stream of [`StackItem`]s representing each node in post-order. The last
/// item yielded is always the root.
fn merkle_stream_post_order<T>(
    stream: impl Stream<Item = T> + Unpin,
) -> impl Stream<Item = StackItem> + Unpin
where
    T: Encodable,
{
    // Hash each item and delegate to the hash-based implementation
    let hash_stream = stream.map(|item| item.consensus_hash_sha256());
    merkle_stream_post_order_hashes(hash_stream)
}

/// Same as [`merkle_stream_post_order`] but accepting a stream of pre-hashed
/// items.
fn merkle_stream_post_order_hashes(
    mut stream: impl Stream<Item = sha256::Hash> + Unpin,
) -> impl Stream<Item = StackItem> + Unpin {
    Box::pin(async_stream::stream! {
        let mut stack = Vec::new();

        while let Some(hash) = stream.next().await {
            let stack_item = StackItem {
                hash,
                depth: 0,
            };
            yield stack_item;
            stack.push(stack_item);

            while let Some((left, right)) = pop_siblings(&mut stack) {
                let combined = (&left.hash, &right.hash).consensus_hash_sha256();
                let stack_item = StackItem {
                    hash: combined,
                    depth: left.depth + 1,
                };
                yield stack_item;
                stack.push(stack_item);
            }
        }

        // Add padding if number of items wasn't a power of 2.
        //   * If stream was empty, we'll add one padding item.
        //   * If stream had an odd number of items, we'll add padding items until the number of items is a power of 2.
        let padding = sha256::Hash::all_zeros();
        while stack.len() != 1 {
            let first_padding_item = StackItem { hash: padding, depth: 0 };
            yield first_padding_item;
            stack.push(first_padding_item);
            while let Some((left, right)) = pop_siblings(&mut stack) {
                let combined = (&left.hash, &right.hash).consensus_hash_sha256();
                let padding_item = StackItem {
                    hash: combined,
                    depth: left.depth + 1,
                };
                yield padding_item;
                stack.push(padding_item);
            }
        }
    })
}

/// A node in the merkle tree during construction.
///
/// Used internally by [`merkle_stream_post_order`] to track nodes
/// on the stack as the tree is built bottom-up.
#[derive(Debug, Copy, Clone)]
struct StackItem {
    /// The hash of this node: `Hash(item)` for leaves,
    /// `Hash(left, right)` for internal nodes.
    hash: sha256::Hash,
    /// Depth from the bottom of the tree. Leaves have depth 0,
    /// and depth increases toward the root.
    depth: u32,
}

impl StackItem {
    /// Returns `true` if this is a padding node (zero hash).
    ///
    /// Padding nodes are added when the number of leaves is not a power of 2.
    fn is_padding(&self) -> bool {
        self.hash == sha256::Hash::all_zeros()
    }

    /// Returns `true` if this is a leaf node (depth 0).
    fn is_leaf(&self) -> bool {
        self.depth == 0
    }
}

/// Pop the top two items from the stack if they have the same depth.
/// Returned as `(left, right)`.
fn pop_siblings(stack: &mut Vec<StackItem>) -> Option<(StackItem, StackItem)> {
    if stack.len() < 2 {
        return None;
    }

    let right_depth = stack[stack.len() - 1].depth;
    let left_depth = stack[stack.len() - 2].depth;

    if left_depth != right_depth {
        return None;
    }

    let right = stack.pop().unwrap();
    let left = stack.pop().unwrap();
    Some((left, right))
}

/// Returns a mutable reference to the element at `index`, inserting defaults if
/// needed.
///
/// If `index` is beyond the current length of the vector, the vector is
/// extended with default values until `index` is valid.
fn get_mut_or_insert<T: Default>(vec: &mut Vec<T>, index: usize) -> &mut T {
    if index >= vec.len() {
        vec.resize_with(index + 1, || T::default());
    }
    vec.get_mut(index)
        .expect("Just inserted elements up to this index, so this can never fail")
}

impl<T: Encodable + 'static> Encodable for ChunkMerkleProof<T> {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.num_leaves.consensus_encode(writer)?;
        self.chunk_size.consensus_encode(writer)?;
        self.merkle_path.consensus_encode(writer)?;
        self.chunk.consensus_encode(writer)?;
        Ok(())
    }
}

impl<T: Decodable + 'static> Decodable for ChunkMerkleProof<T> {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let num_leaves = u64::consensus_decode_partial(r, modules)?;
        let chunk_size = u64::consensus_decode_partial(r, modules)?;
        let merkle_path = Vec::<MerklePathItem>::consensus_decode_partial(r, modules)?;
        let chunk = Vec::<T>::consensus_decode_partial(r, modules)?;
        Ok(ChunkMerkleProof {
            num_leaves,
            chunk_size,
            merkle_path,
            chunk,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use super::*;

    #[tokio::test]
    async fn test_chunk_merkle_proofs() {
        const CHUNK_SIZES: [usize; 5] = [2, 4, 8, 16, 32];
        const NUM_LEAVES: RangeInclusive<usize> = 0..=1024;

        for chunk_size in CHUNK_SIZES {
            for num_leaves in NUM_LEAVES {
                let item_stream = (0..num_leaves).map(|i| i as u64).collect::<Vec<_>>();

                let merkle_root =
                    MerkleRoot::from_stream(futures::stream::iter(item_stream.clone())).await;
                let mut chunk_merkle_proof_stream = chunk_merkle_proof_stream(
                    || futures::stream::iter(item_stream.clone()),
                    chunk_size as u64,
                )
                .await
                .enumerate();

                while let Some((chunk_index, chunk_merkle_proof)) =
                    chunk_merkle_proof_stream.next().await
                {
                    assert!(
                        merkle_root
                            .verify_chunk_merkle_proof(&chunk_merkle_proof)
                            .await,
                        "Chunk {chunk_index} of size {chunk_size} of a total of {num_leaves} items failed to verify"
                    );
                }
            }
        }
    }
}

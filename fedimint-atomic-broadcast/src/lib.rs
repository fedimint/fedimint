//! This module implements fedimints custom atomic broadcast abstraction. A such, it is
//! responsible for ordering serialized items in the form of byte vectors. The Broadcast is
//! able to recover from a crash at any time via a backup that it maintains in the 
//! servers [fedimint_core::db::Database]. In Addition, it stores the history of accepted 
//! items in the form of [SignedBlock]s in the database as well in order to catch up 
//! fellow guardians which have been offline for a prolonged period of time.
//! 
//! # Example Setup
//! 
//! ```ignore
//! let block_index = 0;
//! let (mempool_item_sender, mempool_item_receiver) = async_channel::bounded(256);
//! let (incoming_message_sender, incoming_message_receiver) = async_channel::bounded(256);
//! let (outgoing_message_sender, outgoing_message_receiver) = async_channel::bounded(256);
//! let (ordered_item_sender, ordered_item_receiver) = mpsc::channel(1);
//! let (shutdown_sender, shutdown_receiver) = watch::channel(None);
//!
//! let broadcast_handle = tokio::spawn(fedimint_atomic_broadcast::run(
//!    keychain,
//!    db,
//!    block_index,
//!    mempool_item_receiver,
//!    incoming_message_receiver,
//!    outgoing_message_sender,
//!    ordered_item_sender,
//!    shutdown_receiver,
//! ));
//! ```
//! 
//! We now sketch out the journey of an [fedimint_core::epoch::ConsensusItem] into a signed block.
//! 
//! * The node which wants to order the item calls consensus_encode to serialize it and sends
//!   the resulting serialization it to its running atomic broadcast instance via the mempool item sender.
//! * Every 250ms the broadcasts currently running session instance creates a new batch from its mempool
//!   and attaches it to a Unit in the form of UnitData::Batch. The size of a batch and therfore the size
//!   of a serialization is limited to 10kB.
//! * The unit is then included in a [Message] and send to the server via the outgoing message sender.
//! * The server receives the message, serializes it via consensus_encode and sends it to its peers, 
//!   which in turn deserialize it via consensus_decode and relay it to their broadcast instance via 
//!   their incoming message sender.
//! * When the unit eventually gets ordered after roughly a second so is our attached batch. 
//!   The broadcast instances unpacks the batch send the serialization in an [OrderedItem] to Fedimint Consensus.
//! * Fedimint Consensus then deserializes the item and either accepts the item if it is valid according to
//!   the current consensus state or discards it otherwise. Fedimint Consensus transmits its decision to
//!   its broadcast instance via the decision_sender and processes the next item.
//! * Assuming our item has been accepted the broadcast instance appends its deserialization to the block
//!   corresponding to the current session.
//! * Roughly every five minutes the session completes at which point the broadcast creates a threshold signature
//!   for the blocks header and saves both in the form of a [SignedBlock] in the local database.

mod broadcast;
mod conversion;
mod data_provider;
mod db;
mod finalization_handler;
mod keychain;
mod network;
mod session;
mod spawner;

use bitcoin::merkle_tree;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use fedimint_core::{
    encoding::{Decodable, Encodable},
    PeerId,
};
use tokio::sync::oneshot;

/// This function runs the broadcast until a shutdown is intiated either via the 
/// shutdown sender or the [OrderedItem] receiver is dropped.
pub use broadcast::run;

/// This keychain implements naive threshold schnorr signatures over secp256k1.
/// The broadcasts uses this keychain to sign messages for other nodes and create
/// the threshold signatures for the signed blocks.
pub use keychain::Keychain;

/// The majority of these messages need to be delivered to the intended [Recipient]
/// in order for the broadcast to make progress. However, the broadcast does not assume
/// a reliable network layer and implements all necessary retry logic. Therefore, the
/// caller just has to try to send the message once and can otherwise discard it immediatly.
#[derive(Clone,Debug, Encodable, Decodable)]
pub enum Message {
    NetworkData(Vec<u8>),
    BlockRequest(u64),
    Block(SignedBlock),
}

/// This enum defines the intented destination of a [Message].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Everyone,
    Peer(PeerId),
}

/// This enum specifies wether an [OrderedItem] has been accepted or discarded
/// by the Fedimint Consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Discard,
}

/// If two correct nodes obtain two ordered items from the broadcast they
/// are guaranteed to be in the same order. However, an ordered items is
/// only guaranteed to be seen by all correct nodes if and only if a correct
/// node decidecs to accept and item.
#[derive(Debug)]
pub struct OrderedItem {
    pub item: Vec<u8>,
    pub block_index: u64,
    pub peer_id: PeerId,
    pub decision_sender: oneshot::Sender<Decision>,
}

/// An accepted item is created and recorded in the corresponding block if and only
/// if  Fedimint Consensus decides to accept an [OrderedItem].
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct AcceptedItem {
    pub item: Vec<u8>,
    pub peer_id: PeerId,
}

/// All items ordered in a session that have been accepted by Fedimint Consensus
/// are recorded in the corresponding block. A running Federation produces a [Block]
/// roughly every five minutes.  Therefore, just like in Bitcoin, a [Block]
/// might be empty if no items are ordered in that time or all ordered items
/// are discarded by Fedimint Consensus.
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct Block {
    pub index: u64,
    pub items: Vec<AcceptedItem>,
}

impl Block {
    /// A blocks header consists of 40 bytes formed by its index in big endian bytes
    /// concatenated with the merkle root build from the consensus hashes of its [AcceptedItem]s 
    /// or 32 zero bytes if the block is empty. The use of a merkle tree allows for 
    /// efficient inclusion proofs of accepted consensus items for clients.
    pub fn header(&self) -> [u8; 40] {
        let mut header = [0; 40];

        header[..8].copy_from_slice(&self.index.to_be_bytes());

        let leaf_hashes = self.items.iter().map(|item| {
            let mut engine = sha256::HashEngine::default();
            item.consensus_encode(&mut engine)
                .expect("Writing to HashEngine cannot fail");
            sha256::Hash::from_engine(engine)
        });

        if let Some(root) = merkle_tree::calculate_root(leaf_hashes) {
            header[8..].copy_from_slice(&root.to_byte_array());
        }

        header
    }
}

/// A signed block combines a block with the naive threshold secp schnorr signature
/// for its header created by the federation. The signed blocks allow clients and 
/// recovering guardians to verify the federations consensus history. After a signed
/// block has been created it is stored in the database.
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignedBlock {
    pub block: Block,
    pub signature: std::collections::BTreeMap<PeerId, [u8; 64]>,
}

/// A clean shutdown can be initiated at the end of every session via the shutdown 
/// sender passed to [run]. This can be used for a coordinated shutdown of a federation
/// in order to upgrade. A mid session shutdown is triggered if the receiver for the 
/// [OrderedItem]s is dropped. This mechanism can be used if one wants to shut down 
/// a single guardian immediatly.
#[derive(Debug, PartialEq, Eq)]
pub enum Shutdown {
    Clean(u64),
    MidSession(u64),
}

//! This module implements fedimints custom atomic broadcast abstraction. A
//! such, it is responsible for ordering serialized items in the form of byte
//! vectors. The Broadcast is able to recover from a crash at any time via a
//! backup that it maintains in the servers [fedimint_core::db::Database]. In
//! Addition, it stores the history of accepted items in the form of
//! [SignedBlock]s in the database as well in order to catch up fellow guardians
//! which have been offline for a prolonged period of time.
//!
//! Though the broadcast depends on [fedimint_core] for [fedimint_core::PeerId],
//! [fedimint_core::encoding::Encodable] and [fedimint_core::db::Database]
//! it implements no consensus logic specific to Fedimint, to which we will
//! refer as Fedimint Consensus going forward. To the broadcast a consensus item
//! is merely a vector of bytes without any further structure.
//!
//! # The journey of a ConsensusItem
//!
//! Let us sketch the journey of an [fedimint_core::epoch::ConsensusItem] into a
//! signed block.
//!
//! * The node which wants to order the item calls consensus_encode to serialize
//!   it and sends the resulting serialization to its running atomic broadcast
//!   instance via the mempool item sender.
//! * Every 250ms the broadcasts currently running session instance creates a
//!   new batch from its mempool and attaches it to a unit in the form of a
//!   UnitData::Batch. The size of a batch and therefore the size of a
//!   serialization is limited to 10kB.
//! * The unit is then included in a [Message] and send to the network layer via
//!   the outgoing message sender.
//! * The network layer receives the message, serializes it via consensus_encode
//!   and sends it to its peers, which in turn deserialize it via
//!   consensus_decode and relay it to their broadcast instance via their
//!   incoming message sender.
//! * The unit is added to the local subgraph of a common directed acyclic graph
//!   of units generated cooperatively by all peers for every session.
//! * As the local subgraph grows the units within it are ordered and so are the
//!   attached batches. As soon as it is ordered the broadcast instances unpacks
//!   our batch sends the serialization to Fedimint Consensus in the form of an
//!   [OrderedItem] .
//! * Fedimint Consensus then deserializes the item and either accepts the item
//!   bases on its current consensus state or discards it otherwise. Fedimint
//!   Consensus transmits its decision to its broadcast instance via the
//!   decision_sender and processes the next item.
//! * Assuming our item has been accepted the broadcast instance appends its
//!   deserialization is added to the block corresponding to the current
//!   session.
//! * Roughly every five minutes the session completes. Then the broadcast
//!   creates a threshold signature for the blocks header and saves both in the
//!   form of a [SignedBlock] in the local database.
//!
//! # Interplay with Fedimint Consensus
//!
//! As an item is only recorded in a block if it has been accepted the decision
//! has to be consisted for all correct nodes in order for them to create
//! identical blocks for every session. We introduce this complexity in order to
//! prevent a critical DOS vector were a client submits conflicting items, like
//! double spending an ecash note for example, to different peers. If Fedimint
//! Consensus would not be able to discard the conflicting items in such a way
//! that they do not become part of the broadcasts history all of those items
//! would need to be maintained on disk indefinitely.
//!
//! Therefore it cannot be guaranteed that all broadcast instances return the
//! exact stream of ordered items. However, if two correct peers obtain two
//! ordered items from their broadcast instances they are guaranteed to be in
//! the same order. Furthermore, an ordered items is guaranteed to be seen by
//! all correct nodes if a correct peer accepts it. Those two guarantees are
//! sufficient to build consistent replicated state machines like Fedimint
//! Consensus on top of the broadcast. Such a state machine has to accept an
//! item if it changes the machines state and should discard it otherwise. Let
//! us consider the case of an ecash note being double spend by the items
//! A and B while one peer is offline. First, item A is ordered and all correct
//! peers include the note as spent in their state. Therefore they also accept
//! the item A. Then, item B is ordered and all correct nodes notice the double
//! spend and make no changes to their state. Now they can safely discard the
//! item B as it did not cause a state transition. When the session completes
//! only item A is part of the corresponding block. When the offline peer comes
//! back online it downloads the block. Therefore the recovering peer will only
//! see Item A but arrives at the same state as its peers at the end of the
//! session regardless. However, it did so by processing one less ordered item
//! and without realizing that a double spend had occurred.

mod broadcast;
mod conversion;
mod data_provider;
mod db;
mod finalization_handler;
mod integration;
mod keychain;
mod network;
mod session;
mod spawner;

/// The atomic broadcast instance run once by every peer.
pub use broadcast::AtomicBroadcast;
use fedimint_core::block::SignedBlock;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::PeerId;
/// This keychain implements naive threshold schnorr signatures over secp256k1.
/// The broadcasts uses this keychain to sign messages for peers and create
/// the threshold signatures for the signed blocks.
pub use keychain::Keychain;

/// The majority of these messages need to be delivered to the intended
/// [Recipient] in order for the broadcast to make progress. However, the
/// broadcast does not assume a reliable network layer and implements all
/// necessary retry logic. Therefore, the caller can discard a message
/// immediately if its intended recipient is offline.
#[derive(Clone, Debug, Encodable, Decodable)]
pub enum Message {
    NetworkData(Vec<u8>),
    BlockRequest(u64),
    Block(SignedBlock),
}

/// This enum defines the intended destination of a [Message].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Everyone,
    Peer(PeerId),
}

/// This enum specifies whether an [OrderedItem] has been accepted or discarded
/// by Fedimint Consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Discard,
}

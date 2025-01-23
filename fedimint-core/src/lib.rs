#![deny(clippy::pedantic, clippy::nursery)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::future_not_send)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::transmute_ptr_to_ptr)]
#![allow(clippy::unsafe_derive_deserialize)]

//! Fedimint Core library
//!
//! `fedimint-core` contains commonly used types, utilities and primitives,
//! shared between both client and server code.
//!
//! Things that are server-side only typically live in `fedimint-server`, and
//! client-side only in `fedimint-client`.
//!
//! ### Wasm support
//!
//! All code in `fedimint-core` needs to compile on Wasm, and `fedimint-core`
//! includes helpers and wrappers around non-wasm-safe utitlies.
//!
//! In particular:
//!
//! * [`fedimint_core::task`] for task spawning and control
//! * [`fedimint_core::time`] for time-related operations

extern crate self as fedimint_core;

use std::fmt::Debug;
use std::io::Error;
use std::str::FromStr;

pub use amount::*;
/// Mostly re-exported for [`Decodable`] macros.
pub use anyhow;
use bitcoin::address::NetworkUnchecked;
pub use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::{Address, Network};
use lightning::util::ser::Writeable;
use lightning_types::features::Bolt11InvoiceFeatures;
pub use macro_rules_attribute::apply;
pub use peer_id::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use tiered::Tiered;
pub use tiered_multi::*;
pub use {bitcoin, hex, secp256k1};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

/// Admin (guardian) client types
pub mod admin_client;
/// Bitcoin amount types
mod amount;
/// Federation-stored client backups
pub mod backup;
/// Legacy serde encoding for `bls12_381`
pub mod bls12_381_serde;
/// Federation configuration
pub mod config;
/// Fundamental types
pub mod core;
/// Database handling
pub mod db;
/// Consensus encoding
pub mod encoding;
pub mod endpoint_constants;
/// Common environment variables
pub mod envs;
pub mod epoch;
/// Formatting helpers
pub mod fmt_utils;
/// Federation invite code
pub mod invite_code;
/// Common macros
#[macro_use]
pub mod macros;
/// Extendable module sysystem
pub mod module;
/// Peer networking
pub mod net;
/// `PeerId` type
mod peer_id;
/// Runtime (wasm32 vs native) differences handling
pub mod runtime;
/// Task handling, including wasm safe logic
pub mod task;
/// Types handling per-denomination values
pub mod tiered;
/// Types handling multiple per-denomination values
pub mod tiered_multi;
/// Time handling, wasm safe functionality
pub mod time;
/// Timing helpers
pub mod timing;
/// Fedimint transaction (inpus + outputs + signature) types
pub mod transaction;
/// Peg-in txo proofs
pub mod txoproof;
/// General purpose utilities
pub mod util;
/// Version
pub mod version;

/// Atomic BFT unit containing consensus items
pub mod session_outcome;

// It's necessary to wrap `hash_newtype!` in a module because the generated code
// references a module called "core", but we export a conflicting module in this
// file.
mod txid {
    use bitcoin::hashes::hash_newtype;
    use bitcoin::hashes::sha256::Hash as Sha256;

    hash_newtype!(
        /// A transaction id for peg-ins, peg-outs and reissuances
        pub struct TransactionId(Sha256);
    );
}
pub use txid::TransactionId;

/// Amount of bitcoin to send, or `All` to send all available funds
#[derive(Debug, Eq, PartialEq, Copy, Hash, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinAmountOrAll {
    All,
    #[serde(untagged)]
    Amount(#[serde(with = "bitcoin::amount::serde::as_sat")] bitcoin::Amount),
}

impl std::fmt::Display for BitcoinAmountOrAll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Amount(amount) => write!(f, "{amount}"),
        }
    }
}

impl FromStr for BitcoinAmountOrAll {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "all" {
            Ok(Self::All)
        } else {
            let amount = Amount::from_str(s)?;
            Ok(Self::Amount(amount.try_into()?))
        }
    }
}

/// `OutPoint` represents a globally unique output in a transaction
///
/// Hence, a transaction ID and the output index is required.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    Encodable,
    Decodable,
)]
pub struct OutPoint {
    /// The referenced transaction ID
    pub txid: TransactionId,
    /// As a transaction may have multiple outputs, this refers to the index of
    /// the output in a transaction
    pub out_idx: u64,
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.out_idx)
    }
}

impl Encodable for TransactionId {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
        let bytes = &self[..];
        writer.write_all(bytes)?;
        Ok(())
    }
}

impl Decodable for TransactionId {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        _modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        Ok(Self::from_byte_array(bytes))
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Ord,
    PartialOrd,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct Feerate {
    pub sats_per_kvb: u64,
}

impl Feerate {
    pub fn calculate_fee(&self, weight: u64) -> bitcoin::Amount {
        let sats = weight_to_vbytes(weight) * self.sats_per_kvb / 1000;
        bitcoin::Amount::from_sat(sats)
    }
}

const WITNESS_SCALE_FACTOR: u64 = bitcoin::constants::WITNESS_SCALE_FACTOR as u64;

/// Converts weight to virtual bytes, defined in [BIP-141] as weight / 4
/// (rounded up to the next integer).
///
/// [BIP-141]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations
pub fn weight_to_vbytes(weight: u64) -> u64 {
    weight.div_ceil(WITNESS_SCALE_FACTOR)
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Mismatching outcome variant: expected {0}, got {1}")]
    MismatchingVariant(&'static str, &'static str),
}

// Encode features for a bolt11 invoice without encoding the length.
// This functionality was available in `lightning` v0.0.123, but has since been
// removed. See the original code here:
// https://docs.rs/lightning/0.0.123/src/lightning/ln/features.rs.html#745-750
// https://docs.rs/lightning/0.0.123/src/lightning/ln/features.rs.html#1008-1012
pub fn encode_bolt11_invoice_features_without_length(features: &Bolt11InvoiceFeatures) -> Vec<u8> {
    let mut feature_bytes = vec![];
    for f in features.le_flags().iter().rev() {
        f.write(&mut feature_bytes)
            .expect("Writing to byte vec can't fail");
    }
    feature_bytes
}

/// Outputs hex into an object implementing `fmt::Write`.
///
/// Vendored from `bitcoin_hashes` v0.11.0:
/// <https://docs.rs/bitcoin_hashes/0.11.0/src/bitcoin_hashes/hex.rs.html#173-189>
pub fn format_hex(data: &[u8], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let prec = f.precision().unwrap_or(2 * data.len());
    let width = f.width().unwrap_or(2 * data.len());
    for _ in (2 * data.len())..width {
        f.write_str("0")?;
    }
    for ch in data.iter().take(prec / 2) {
        write!(f, "{:02x}", *ch)?;
    }
    if prec < 2 * data.len() && prec % 2 == 1 {
        write!(f, "{:x}", data[prec / 2] / 16)?;
    }
    Ok(())
}

/// Gets the (approximate) network from a bitcoin address.
///
/// This function mimics how `Address.network` is calculated in bitcoin v0.30.
/// However, that field was removed in more recent versions in part because it
/// can only distinguish between `Bitcoin`, `Testnet` and `Regtest`.
///
/// As of bitcoin v0.32.4, `Address::is_valid_for_network()` performs equality
/// checks using `NetworkKind` and `KnownHrp`, which only distinguish between
/// `Bitcoin`, `Testnet` and `Regtest`.
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/address/mod.rs.html#709-716>
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/network.rs.html#51-58>
/// <https://docs.rs/bitcoin/0.32.4/src/bitcoin/address/mod.rs.html#200-209>
pub fn get_network_for_address(address: &Address<NetworkUnchecked>) -> Network {
    if address.is_valid_for_network(Network::Bitcoin) {
        Network::Bitcoin
    } else if address.is_valid_for_network(Network::Testnet) {
        Network::Testnet
    } else if address.is_valid_for_network(Network::Regtest) {
        Network::Regtest
    } else {
        panic!("Address is not valid for any network");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_weight_to_vbytes() {
        assert_eq!(1, weight_to_vbytes(4));
        assert_eq!(2, weight_to_vbytes(5));
    }

    #[test]
    fn calculate_fee() {
        let feerate = Feerate { sats_per_kvb: 1000 };
        assert_eq!(bitcoin::Amount::from_sat(25), feerate.calculate_fee(100));
        assert_eq!(bitcoin::Amount::from_sat(26), feerate.calculate_fee(101));
    }

    #[test]
    fn test_deserialize_amount_or_all() {
        let all: BitcoinAmountOrAll = serde_json::from_str("\"all\"").unwrap();
        assert_eq!(all, BitcoinAmountOrAll::All);

        let amount: BitcoinAmountOrAll = serde_json::from_str("12345").unwrap();
        assert_eq!(
            amount,
            BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(12345))
        );

        let all_string = all.to_string();
        assert_eq!(all_string, "all");
        let amount_string = amount.to_string();
        assert_eq!(amount_string, "0.00012345 BTC");
        let all_parsed = BitcoinAmountOrAll::from_str(&all_string).unwrap();
        assert_eq!(all, all_parsed);
        let amount_parsed = BitcoinAmountOrAll::from_str(&amount_string).unwrap();
        assert_eq!(amount, amount_parsed);
    }
}

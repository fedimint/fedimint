//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.
//!
//! ## Attention: only one operation per contract and round
//! If this module is active the consensus' conflict filter must ensure that at
//! most one operation (spend, funding) happens per contract per round

extern crate core;

pub mod config;
pub mod contracts;
pub mod db;
use std::time::SystemTime;

use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleGen, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, Amount};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;
use url::Url;

use crate::contracts::incoming::OfferId;
use crate::contracts::{Contract, ContractId, ContractOutcome, Preimage, PreimageDecryptionShare};

const KIND: ModuleKind = ModuleKind::from_static_str("ln");
const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct LightningInput {
    pub contract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to
    /// avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other
    /// witness data than a signature. The signature is aggregated on the
    /// transaction level, so only the optional preimage remains.
    pub witness: Option<Preimage>,
}

impl std::fmt::Display for LightningInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lightning Contract {} with amount {}",
            self.contract_id, self.amount
        )
    }
}

/// Represents an output of the Lightning module.
///
/// There are three sub-types:
///   * Normal contracts users may lock funds in
///   * Offers to buy preimages (see `contracts::incoming` docs)
///   * Early cancellation of outgoing contracts before their timeout
///
/// The offer type exists to register `IncomingContractOffer`s. Instead of
/// patching in a second way of letting clients submit consensus items outside
/// of transactions we let offers be a 0-amount output. We need to take care to
/// allow 0-input, 1-output transactions for that to allow users to receive
/// their fist notes via LN without already having notes.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutput {
    /// Fund contract
    Contract(ContractOutput),
    /// Create incoming contract offer
    Offer(contracts::incoming::IncomingContractOffer),
    /// Allow early refund of outgoing contract
    CancelOutgoing {
        /// Contract to update
        contract: ContractId,
        /// Signature of gateway
        gateway_signature: secp256k1::schnorr::Signature,
    },
}

impl std::fmt::Display for LightningOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutput::Contract(ContractOutput { amount, contract }) => match contract {
                Contract::Incoming(incoming) => {
                    write!(
                        f,
                        "LN Incoming Contract for {} hash {}",
                        amount, incoming.hash
                    )
                }
                Contract::Outgoing(outgoing) => {
                    write!(
                        f,
                        "LN Outgoing Contract for {} hash {}",
                        amount, outgoing.hash
                    )
                }
            },
            LightningOutput::Offer(offer) => {
                write!(f, "LN offer for {} with hash {}", offer.amount, offer.hash)
            }
            LightningOutput::CancelOutgoing { contract, .. } => {
                write!(f, "LN outgoing contract cancellation {contract}")
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub amount: fedimint_core::Amount,
    pub contract: contracts::Contract,
}

#[derive(Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize, Clone)]
pub struct ContractAccount {
    pub amount: fedimint_core::Amount,
    pub contract: contracts::FundedContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputOutcome {
    Contract {
        id: ContractId,
        outcome: ContractOutcome,
    },
    Offer {
        id: OfferId,
    },
}

impl LightningOutputOutcome {
    pub fn is_permanent(&self) -> bool {
        match self {
            LightningOutputOutcome::Contract { id: _, outcome } => outcome.is_permanent(),
            LightningOutputOutcome::Offer { .. } => true,
        }
    }
}

impl std::fmt::Display for LightningOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutputOutcome::Contract { id, .. } => {
                write!(f, "LN Contract {id}")
            }
            LightningOutputOutcome::Offer { id } => {
                write!(f, "LN Offer {id}")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq, Hash)]
pub struct LightningGateway {
    /// Channel identifier assigned to the mint by the gateway.
    /// All clients in this federation should use this value as
    /// `short_channel_id` when creating invoices to be settled by this
    /// gateway.
    pub mint_channel_id: u64,
    pub mint_pub_key: secp256k1::XOnlyPublicKey,
    pub node_pub_key: secp256k1::PublicKey,
    pub api: Url,
    /// Route hints to reach the LN node of the gateway.
    ///
    /// These will be appended with the route hint of the recipient's virtual
    /// channel. To keeps invoices small these should be used sparingly.
    pub route_hints: Vec<route_hints::RouteHint>,
    /// Limits the validity of the announcement to allow updates
    pub valid_until: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct LightningConsensusItem {
    pub contract_id: ContractId,
    pub share: PreimageDecryptionShare,
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LN Decryption Share for contract {}", self.contract_id)
    }
}

#[derive(Debug)]
pub struct LightningCommonGen;

impl CommonModuleGen for LightningCommonGen {
    const KIND: ModuleKind = KIND;
    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub struct LightningModuleTypes;

impl ModuleCommon for LightningModuleTypes {
    type Input = LightningInput;
    type Output = LightningOutput;
    type OutputOutcome = LightningOutputOutcome;
    type ConsensusItem = LightningConsensusItem;
}

plugin_types_trait_impl_common!(
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem
);

// TODO: upstream serde support to LDK
/// Hack to get a route hint that implements `serde` traits.
pub mod route_hints {
    use fedimint_core::encoding::{Decodable, Encodable};
    use secp256k1::PublicKey;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
    pub struct RouteHintHop {
        /// The `node_id` of the non-target end of the route
        pub src_node_id: PublicKey,
        /// The `short_channel_id` of this channel
        pub short_channel_id: u64,
        /// Flat routing fee in millisatoshis
        pub base_msat: u32,
        /// Liquidity-based routing fee in millionths of a routed amount.
        /// In other words, 10000 is 1%.
        pub proportional_millionths: u32,
        /// The difference in CLTV values between this node and the next node.
        pub cltv_expiry_delta: u16,
        /// The minimum value, in msat, which must be relayed to the next hop.
        pub htlc_minimum_msat: Option<u64>,
        /// The maximum value in msat available for routing with a single HTLC.
        pub htlc_maximum_msat: Option<u64>,
    }

    /// A list of hops along a payment path terminating with a channel to the
    /// recipient.
    #[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
    pub struct RouteHint(pub Vec<RouteHintHop>);

    impl RouteHint {
        pub fn to_ldk_route_hint(&self) -> lightning::routing::router::RouteHint {
            lightning::routing::router::RouteHint(
                self.0
                    .iter()
                    .map(|hop| lightning::routing::router::RouteHintHop {
                        src_node_id: hop.src_node_id,
                        short_channel_id: hop.short_channel_id,
                        fees: lightning::routing::gossip::RoutingFees {
                            base_msat: hop.base_msat,
                            proportional_millionths: hop.proportional_millionths,
                        },
                        cltv_expiry_delta: hop.cltv_expiry_delta,
                        htlc_minimum_msat: hop.htlc_minimum_msat,
                        htlc_maximum_msat: hop.htlc_maximum_msat,
                    })
                    .collect(),
            )
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LightningError {
    #[error("The the input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("An outgoing LN contract spend did not provide a preimage")]
    MissingPreimage,
    #[error("An outgoing LN contract spend provided a wrong preimage")]
    InvalidPreimage,
    #[error("Incoming contract not ready to be spent yet, decryption in progress")]
    ContractNotReady,
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Offer contains invalid threshold-encrypted data")]
    InvalidEncryptedPreimage,
    #[error(
        "The incoming LN account requires more funding according to the offer (need {0} got {1})"
    )]
    InsufficientIncomingFunding(Amount, Amount),
    #[error("No offer found for payment hash {0}")]
    NoOffer(secp256k1::hashes::sha256::Hash),
    #[error("Only outgoing contracts support cancellation")]
    NotOutgoingContract,
    #[error("Cancellation request wasn't properly signed")]
    InvalidCancellationSignature,
}

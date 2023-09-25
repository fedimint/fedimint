//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.
//!
//! ## Attention: only one operation per contract and round
//! If this module is active the consensus' conflict filter must ensure that at
//! most one operation (spend, funding) happens per contract per round

extern crate core;

pub mod api;
pub mod config;
pub mod contracts;
pub mod db;
pub mod incoming;

use std::time::{Duration, SystemTime};

use anyhow::bail;
use bitcoin_hashes::sha256;
use config::LightningClientConfig;
use fedimint_client::oplog::OperationLogEntry;
use fedimint_client::sm::{Context, OperationId};
use fedimint_client::Client;
use fedimint_core::api::DynModuleApi;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::task::timeout;
use fedimint_core::util::SafeUrl;
use fedimint_core::{plugin_types_trait_impl_common, Amount};
use lightning::routing::gossip::RoutingFees;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::api::LnFederationApi;
use crate::contracts::incoming::{IncomingContract, IncomingContractOffer, OfferId};
use crate::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, IdentifiableContract, Preimage,
    PreimageDecryptionShare,
};
use crate::incoming::IncomingSmError;

pub const KIND: ModuleKind = ModuleKind::from_static_str("ln");
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
/// their first notes via LN without already having notes.
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
    CancelOutgoingContract {
        id: ContractId,
    },
}

impl LightningOutputOutcome {
    pub fn is_permanent(&self) -> bool {
        match self {
            LightningOutputOutcome::Contract { id: _, outcome } => outcome.is_permanent(),
            LightningOutputOutcome::Offer { .. } => true,
            LightningOutputOutcome::CancelOutgoingContract { .. } => true,
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
            LightningOutputOutcome::CancelOutgoingContract { id: contract_id } => {
                write!(f, "LN Outgoing Contract Cancellation {contract_id}")
            }
        }
    }
}

/// Information a gateway registers with a fed
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq, Hash)]
pub struct LightningGateway {
    /// Channel identifier assigned to the mint by the gateway.
    /// All clients in this federation should use this value as
    /// `short_channel_id` when creating invoices to be settled by this
    /// gateway.
    pub mint_channel_id: u64,
    /// Key used to pay the gateway
    pub gateway_redeem_key: secp256k1::XOnlyPublicKey,
    pub node_pub_key: secp256k1::PublicKey,
    pub lightning_alias: String,
    pub api: SafeUrl,
    /// Route hints to reach the LN node of the gateway.
    ///
    /// These will be appended with the route hint of the recipient's virtual
    /// channel. To keeps invoices small these should be used sparingly.
    pub route_hints: Vec<route_hints::RouteHint>,
    /// Limits the validity of the announcement to allow updates
    pub valid_until: SystemTime,
    /// Gateway configured routing fees
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
    pub gateway_id: secp256k1::PublicKey,
}

impl LightningGateway {
    pub fn is_expired(&self) -> bool {
        self.valid_until < fedimint_core::time::now()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum LightningConsensusItem {
    DecryptPreimage(ContractId, PreimageDecryptionShare),
    BlockCount(u64),
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningConsensusItem::DecryptPreimage(contract_id, _) => {
                write!(f, "LN Decryption Share for contract {contract_id}")
            }
            LightningConsensusItem::BlockCount(count) => write!(f, "LN block count {count}"),
        }
    }
}

#[derive(Debug)]
pub struct LightningCommonGen;

impl CommonModuleInit for LightningCommonGen {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub struct LightningModuleTypes;

plugin_types_trait_impl_common!(
    LightningModuleTypes,
    LightningClientConfig,
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem
);

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    pub ln_decoder: Decoder,
    pub redeem_key: bitcoin::KeyPair,
}

impl Context for LightningClientContext {}

// TODO: upstream serde support to LDK
/// Hack to get a route hint that implements `serde` traits.
pub mod route_hints {
    use fedimint_core::encoding::{Decodable, Encodable};
    use lightning::routing::gossip::RoutingFees;
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
                        fees: RoutingFees {
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

// TODO: Upstream serde serialization for
// lightning::routing::gossip::RoutingFees
// See https://github.com/lightningdevkit/rust-lightning/blob/b8ed4d2608e32128dd5a1dee92911638a4301138/lightning/src/routing/gossip.rs#L1057-L1065
pub mod serde_routing_fees {
    use lightning::routing::gossip::RoutingFees;
    use serde::ser::SerializeStruct;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(missing_docs)]
    pub fn serialize<S>(fees: &RoutingFees, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RoutingFees", 2)?;
        state.serialize_field("base_msat", &fees.base_msat)?;
        state.serialize_field("proportional_millionths", &fees.proportional_millionths)?;
        state.end()
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RoutingFees, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fees = serde_json::Value::deserialize(deserializer)?;
        // While we deserialize fields as u64, RoutingFees expects u32 for the fields
        let base_msat = fees["base_msat"]
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("base_msat is not a u64"))?;
        let proportional_millionths = fees["proportional_millionths"]
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("proportional_millionths is not a u64"))?;

        Ok(RoutingFees {
            base_msat: base_msat
                .try_into()
                .map_err(|_| serde::de::Error::custom("base_msat is greater than u32::MAX"))?,
            proportional_millionths: proportional_millionths.try_into().map_err(|_| {
                serde::de::Error::custom("proportional_millionths is greater than u32::MAX")
            })?,
        })
    }
}

pub mod serde_option_routing_fees {
    use lightning::routing::gossip::RoutingFees;
    use serde::ser::SerializeStruct;
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(missing_docs)]
    pub fn serialize<S>(fees: &Option<RoutingFees>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(fees) = fees {
            let mut state = serializer.serialize_struct("RoutingFees", 2)?;
            state.serialize_field("base_msat", &fees.base_msat)?;
            state.serialize_field("proportional_millionths", &fees.proportional_millionths)?;
            state.end()
        } else {
            let state = serializer.serialize_struct("RoutingFees", 0)?;
            state.end()
        }
    }

    #[allow(missing_docs)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<RoutingFees>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fees = serde_json::Value::deserialize(deserializer)?;
        // While we deserialize fields as u64, RoutingFees expects u32 for the fields
        let base_msat = fees["base_msat"].as_u64();

        if let Some(base_msat) = base_msat {
            if let Some(proportional_millionths) = fees["proportional_millionths"].as_u64() {
                let base_msat: u32 = base_msat
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("base_msat is greater than u32::MAX"))?;
                let proportional_millionths: u32 =
                    proportional_millionths.try_into().map_err(|_| {
                        serde::de::Error::custom("proportional_millionths is greater than u32::MAX")
                    })?;
                return Ok(Some(RoutingFees {
                    base_msat,
                    proportional_millionths,
                }));
            }
        }

        Ok(None)
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
    #[error("Offer contains a ciphertext that has already been used")]
    DuplicateEncryptedPreimage,
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

pub async fn ln_operation(
    client: &Client,
    operation_id: OperationId,
) -> anyhow::Result<OperationLogEntry> {
    let operation = client
        .operation_log()
        .get_operation(operation_id)
        .await
        .ok_or(anyhow::anyhow!("Operation not found"))?;

    if operation.operation_module_kind() != LightningCommonGen::KIND.as_str() {
        bail!("Operation is not a lightning operation");
    }

    Ok(operation)
}

async fn fetch_and_validate_offer(
    module_api: &DynModuleApi,
    payment_hash: sha256::Hash,
    amount_msat: Amount,
) -> anyhow::Result<IncomingContractOffer, IncomingSmError> {
    let offer = timeout(Duration::from_secs(5), module_api.fetch_offer(payment_hash))
        .await
        .map_err(|_| IncomingSmError::TimeoutFetchingOffer { payment_hash })?
        .map_err(|e| IncomingSmError::FetchContractError {
            payment_hash,
            error_message: e.to_string(),
        })?;

    if offer.amount > amount_msat {
        return Err(IncomingSmError::ViolatedFeePolicy {
            offer_amount: offer.amount,
            payment_amount: amount_msat,
        });
    }
    if offer.hash != payment_hash {
        return Err(IncomingSmError::InvalidOffer {
            offer_hash: offer.hash,
            payment_hash,
        });
    }
    Ok(offer)
}

pub async fn create_incoming_contract_output(
    module_api: &DynModuleApi,
    payment_hash: sha256::Hash,
    amount_msat: Amount,
    redeem_key: secp256k1::KeyPair,
) -> Result<(LightningOutput, ContractId), IncomingSmError> {
    let offer = fetch_and_validate_offer(module_api, payment_hash, amount_msat).await?;
    let our_pub_key = secp256k1::XOnlyPublicKey::from_keypair(&redeem_key).0;
    let contract = IncomingContract {
        hash: offer.hash,
        encrypted_preimage: offer.encrypted_preimage.clone(),
        decrypted_preimage: DecryptedPreimage::Pending,
        gateway_key: our_pub_key,
    };
    let contract_id = contract.contract_id();
    let incoming_output = LightningOutput::Contract(ContractOutput {
        amount: offer.amount,
        contract: Contract::Incoming(contract),
    });

    Ok((incoming_output, contract_id))
}

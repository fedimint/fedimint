#![deny(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.
//!
//! ## Attention: only one operation per contract and round
//! If this module is active the consensus' conflict filter must ensure that at
//! most one operation (spend, funding) happens per contract per round

pub mod config;
pub mod contracts;
pub mod federation_endpoint_constants;
pub mod gateway_endpoint_constants;

use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Read, Write};
use std::time::{Duration, SystemTime};

use anyhow::Context as AnyhowContext;
use bitcoin::hashes::{Hash, sha256};
use config::LightningClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::Message;
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    Amount, PeerId, encode_bolt11_invoice_features_without_length,
    extensible_associated_module_type, plugin_types_trait_impl_common, secp256k1,
};
use lightning_invoice::{Bolt11Invoice, RoutingFees};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use threshold_crypto::PublicKey;
use tracing::error;
pub use {bitcoin, lightning_invoice};

use crate::contracts::incoming::OfferId;
use crate::contracts::{Contract, ContractId, ContractOutcome, Preimage, PreimageDecryptionShare};
use crate::route_hints::RouteHint;

pub const KIND: ModuleKind = ModuleKind::from_static_str("ln");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 0);

extensible_associated_module_type!(
    LightningInput,
    LightningInputV0,
    UnknownLightningInputVariantError
);

impl LightningInput {
    pub fn new_v0(
        contract_id: ContractId,
        amount: Amount,
        witness: Option<Preimage>,
    ) -> LightningInput {
        LightningInput::V0(LightningInputV0 {
            contract_id,
            amount,
            witness,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct LightningInputV0 {
    pub contract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to
    /// avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other
    /// witness data than a signature. The signature is aggregated on the
    /// transaction level, so only the optional preimage remains.
    pub witness: Option<Preimage>,
}

impl std::fmt::Display for LightningInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lightning Contract {} with amount {}",
            self.contract_id, self.amount
        )
    }
}

extensible_associated_module_type!(
    LightningOutput,
    LightningOutputV0,
    UnknownLightningOutputVariantError
);

impl LightningOutput {
    pub fn new_v0_contract(contract: ContractOutput) -> LightningOutput {
        LightningOutput::V0(LightningOutputV0::Contract(contract))
    }

    pub fn new_v0_offer(offer: contracts::incoming::IncomingContractOffer) -> LightningOutput {
        LightningOutput::V0(LightningOutputV0::Offer(offer))
    }

    pub fn new_v0_cancel_outgoing(
        contract: ContractId,
        gateway_signature: secp256k1::schnorr::Signature,
    ) -> LightningOutput {
        LightningOutput::V0(LightningOutputV0::CancelOutgoing {
            contract,
            gateway_signature,
        })
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
pub enum LightningOutputV0 {
    /// Fund contract
    Contract(ContractOutput),
    /// Create incoming contract offer
    Offer(contracts::incoming::IncomingContractOffer),
    /// Allow early refund of outgoing contract
    CancelOutgoing {
        /// Contract to update
        contract: ContractId,
        /// Signature of gateway
        gateway_signature: fedimint_core::secp256k1::schnorr::Signature,
    },
}

impl std::fmt::Display for LightningOutputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutputV0::Contract(ContractOutput { amount, contract }) => match contract {
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
            LightningOutputV0::Offer(offer) => {
                write!(f, "LN offer for {} with hash {}", offer.amount, offer.hash)
            }
            LightningOutputV0::CancelOutgoing { contract, .. } => {
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

extensible_associated_module_type!(
    LightningOutputOutcome,
    LightningOutputOutcomeV0,
    UnknownLightningOutputOutcomeVariantError
);

impl LightningOutputOutcome {
    pub fn new_v0_contract(id: ContractId, outcome: ContractOutcome) -> LightningOutputOutcome {
        LightningOutputOutcome::V0(LightningOutputOutcomeV0::Contract { id, outcome })
    }

    pub fn new_v0_offer(id: OfferId) -> LightningOutputOutcome {
        LightningOutputOutcome::V0(LightningOutputOutcomeV0::Offer { id })
    }

    pub fn new_v0_cancel_outgoing(id: ContractId) -> LightningOutputOutcome {
        LightningOutputOutcome::V0(LightningOutputOutcomeV0::CancelOutgoingContract { id })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputOutcomeV0 {
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

impl LightningOutputOutcomeV0 {
    pub fn is_permanent(&self) -> bool {
        match self {
            LightningOutputOutcomeV0::Contract { id: _, outcome } => outcome.is_permanent(),
            LightningOutputOutcomeV0::Offer { .. }
            | LightningOutputOutcomeV0::CancelOutgoingContract { .. } => true,
        }
    }
}

impl std::fmt::Display for LightningOutputOutcomeV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutputOutcomeV0::Contract { id, .. } => {
                write!(f, "LN Contract {id}")
            }
            LightningOutputOutcomeV0::Offer { id } => {
                write!(f, "LN Offer {id}")
            }
            LightningOutputOutcomeV0::CancelOutgoingContract { id: contract_id } => {
                write!(f, "LN Outgoing Contract Cancellation {contract_id}")
            }
        }
    }
}

/// Information about a gateway that is stored locally and expires based on
/// local system time
///
/// Should only be serialized and deserialized in formats that can ignore
/// additional fields as this struct may be extended in the future.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LightningGatewayRegistration {
    pub info: LightningGateway,
    /// Indicates if this announcement has been vetted by the federation
    pub vetted: bool,
    /// Limits the validity of the announcement to allow updates, anchored to
    /// local system time
    pub valid_until: SystemTime,
}

impl Encodable for LightningGatewayRegistration {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let json_repr = serde_json::to_string(self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed to serialize LightningGatewayRegistration: {e}"),
            )
        })?;

        json_repr.consensus_encode(writer)
    }
}

impl Decodable for LightningGatewayRegistration {
    fn consensus_decode_partial<R: Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let json_repr = String::consensus_decode_partial(r, modules)?;
        serde_json::from_str(&json_repr).map_err(|e| {
            DecodeError::new_custom(
                anyhow::Error::new(e).context("Failed to deserialize LightningGatewayRegistration"),
            )
        })
    }
}

impl LightningGatewayRegistration {
    /// Create an announcement from this registration that is ttl-limited by
    /// a floating duration. This is useful for sharing the announcement with
    /// other nodes with unsynchronized clocks which can then anchor the
    /// announcement to their local system time.
    pub fn unanchor(self) -> LightningGatewayAnnouncement {
        LightningGatewayAnnouncement {
            info: self.info,
            ttl: self
                .valid_until
                .duration_since(fedimint_core::time::now())
                .unwrap_or_default(),
            vetted: self.vetted,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.valid_until < fedimint_core::time::now()
    }
}

/// Information about a gateway that is shared with other federation members and
/// expires based on a TTL to allow for sharing between nodes with
/// unsynchronized clocks which can each anchor the announcement to their local
/// system time.
///
/// Should only be serialized and deserialized in formats that can ignore
/// additional fields as this struct may be extended in the future.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LightningGatewayAnnouncement {
    pub info: LightningGateway,
    /// Indicates if this announcement has been vetted by the federation
    pub vetted: bool,
    /// Limits the validity of the announcement to allow updates, unanchored to
    /// local system time to allow sharing between nodes with unsynchronized
    /// clocks
    pub ttl: Duration,
}

impl LightningGatewayAnnouncement {
    /// Create a registration from this announcement that is anchored to the
    /// local system time.
    pub fn anchor(self) -> LightningGatewayRegistration {
        LightningGatewayRegistration {
            info: self.info,
            vetted: self.vetted,
            valid_until: fedimint_core::time::now() + self.ttl,
        }
    }
}

/// Information a gateway registers with a federation
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq, Hash)]
pub struct LightningGateway {
    /// Unique per-federation identifier assigned by the gateway.
    /// All clients in this federation should use this value as
    /// `short_channel_id` when creating invoices to be settled by this
    /// gateway.
    #[serde(rename = "mint_channel_id")]
    pub federation_index: u64,
    /// Key used to pay the gateway
    pub gateway_redeem_key: fedimint_core::secp256k1::PublicKey,
    pub node_pub_key: fedimint_core::secp256k1::PublicKey,
    pub lightning_alias: String,
    /// URL to the gateway's versioned public API
    /// (e.g. <https://gateway.example.com/v1>)
    pub api: SafeUrl,
    /// Route hints to reach the LN node of the gateway.
    ///
    /// These will be appended with the route hint of the recipient's virtual
    /// channel. To keeps invoices small these should be used sparingly.
    pub route_hints: Vec<route_hints::RouteHint>,
    /// Gateway configured routing fees
    #[serde(with = "serde_routing_fees")]
    pub fees: RoutingFees,
    pub gateway_id: secp256k1::PublicKey,
    /// Indicates if the gateway supports private payments
    pub supports_private_payments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub enum LightningConsensusItem {
    DecryptPreimage(ContractId, PreimageDecryptionShare),
    BlockCount(u64),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningConsensusItem::DecryptPreimage(contract_id, _) => {
                write!(f, "LN Decryption Share for contract {contract_id}")
            }
            LightningConsensusItem::BlockCount(count) => write!(f, "LN block count {count}"),
            LightningConsensusItem::Default { variant, .. } => {
                write!(f, "Unknown LN CI variant={variant}")
            }
        }
    }
}

#[derive(Debug)]
pub struct LightningCommonInit;

impl CommonModuleInit for LightningCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub struct LightningModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    LightningModuleTypes,
    LightningClientConfig,
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem,
    LightningInputError,
    LightningOutputError
);

// TODO: upstream serde support to LDK
/// Hack to get a route hint that implements `serde` traits.
pub mod route_hints {
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::secp256k1::PublicKey;
    use lightning_invoice::RoutingFees;
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
        pub fn to_ldk_route_hint(&self) -> lightning_invoice::RouteHint {
            lightning_invoice::RouteHint(
                self.0
                    .iter()
                    .map(|hop| lightning_invoice::RouteHintHop {
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

    impl From<lightning_invoice::RouteHint> for RouteHint {
        fn from(rh: lightning_invoice::RouteHint) -> Self {
            RouteHint(rh.0.into_iter().map(Into::into).collect())
        }
    }

    impl From<lightning_invoice::RouteHintHop> for RouteHintHop {
        fn from(rhh: lightning_invoice::RouteHintHop) -> Self {
            RouteHintHop {
                src_node_id: rhh.src_node_id,
                short_channel_id: rhh.short_channel_id,
                base_msat: rhh.fees.base_msat,
                proportional_millionths: rhh.fees.proportional_millionths,
                cltv_expiry_delta: rhh.cltv_expiry_delta,
                htlc_minimum_msat: rhh.htlc_minimum_msat,
                htlc_maximum_msat: rhh.htlc_maximum_msat,
            }
        }
    }
}

// TODO: Upstream serde serialization for
// lightning_invoice::RoutingFees
// See https://github.com/lightningdevkit/rust-lightning/blob/b8ed4d2608e32128dd5a1dee92911638a4301138/lightning/src/routing/gossip.rs#L1057-L1065
pub mod serde_routing_fees {
    use lightning_invoice::RoutingFees;
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
    use lightning_invoice::RoutingFees;
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

#[derive(Debug, Error, Eq, PartialEq, Encodable, Decodable, Hash, Clone)]
pub enum LightningInputError {
    #[error("The input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("An outgoing LN contract spend did not provide a preimage")]
    MissingPreimage,
    #[error("An outgoing LN contract spend provided a wrong preimage")]
    InvalidPreimage,
    #[error("Incoming contract not ready to be spent yet, decryption in progress")]
    ContractNotReady,
    #[error("The lightning input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownLightningInputVariantError),
}

#[derive(Debug, Error, Eq, PartialEq, Encodable, Decodable, Hash, Clone)]
pub enum LightningOutputError {
    #[error("The input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Offer contains invalid threshold-encrypted data")]
    InvalidEncryptedPreimage,
    #[error("Offer contains a ciphertext that has already been used")]
    DuplicateEncryptedPreimage,
    #[error("The incoming LN account requires more funding (need {0} got {1})")]
    InsufficientIncomingFunding(Amount, Amount),
    #[error("No offer found for payment hash {0}")]
    NoOffer(bitcoin::secp256k1::hashes::sha256::Hash),
    #[error("Only outgoing contracts support cancellation")]
    NotOutgoingContract,
    #[error("Cancellation request wasn't properly signed")]
    InvalidCancellationSignature,
    #[error("The lightning output version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownLightningOutputVariantError),
}

/// Data needed to pay an invoice
///
/// This is a subset of the data from a [`lightning_invoice::Bolt11Invoice`]
/// that does not contain the description, which increases privacy for the user.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub struct PrunedInvoice {
    pub amount: Amount,
    pub destination: secp256k1::PublicKey,
    /// Wire-format encoding of feature bit vector
    #[serde(with = "fedimint_core::hex::serde", default)]
    pub destination_features: Vec<u8>,
    pub payment_hash: sha256::Hash,
    pub payment_secret: [u8; 32],
    pub route_hints: Vec<RouteHint>,
    pub min_final_cltv_delta: u64,
    /// Time at which the invoice expires in seconds since unix epoch
    pub expiry_timestamp: u64,
}

impl PrunedInvoice {
    pub fn new(invoice: &Bolt11Invoice, amount: Amount) -> Self {
        // We use expires_at since it doesn't rely on the std feature in
        // lightning-invoice. See #3838.
        let expiry_timestamp = invoice.expires_at().map_or(u64::MAX, |t| t.as_secs());

        let destination_features = if let Some(features) = invoice.features() {
            encode_bolt11_invoice_features_without_length(features)
        } else {
            vec![]
        };

        PrunedInvoice {
            amount,
            destination: invoice
                .payee_pub_key()
                .copied()
                .unwrap_or_else(|| invoice.recover_payee_pub_key()),
            destination_features,
            payment_hash: *invoice.payment_hash(),
            payment_secret: invoice.payment_secret().0,
            route_hints: invoice.route_hints().into_iter().map(Into::into).collect(),
            min_final_cltv_delta: invoice.min_final_cltv_expiry_delta(),
            expiry_timestamp,
        }
    }
}

impl TryFrom<Bolt11Invoice> for PrunedInvoice {
    type Error = anyhow::Error;

    fn try_from(invoice: Bolt11Invoice) -> Result<Self, Self::Error> {
        Ok(PrunedInvoice::new(
            &invoice,
            Amount::from_msats(
                invoice
                    .amount_milli_satoshis()
                    .context("Invoice amount is missing")?,
            ),
        ))
    }
}

/// Request sent to the federation that requests the removal of a gateway
/// registration. Each peer is expected to check the `signatures` map for the
/// signature that validates the gateway authorized the removal of this
/// registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveGatewayRequest {
    pub gateway_id: secp256k1::PublicKey,
    pub signatures: BTreeMap<PeerId, Signature>,
}

/// Creates a message to be signed by the Gateway's private key for the purpose
/// of removing the gateway's registration record. Message is defined as:
///
/// msg = sha256(tag + federation_public_key + peer_id + challenge)
///
/// Tag is always `remove_gateway`. Challenge is unique for the registration
/// record and acquired from each guardian prior to the removal request.
pub fn create_gateway_remove_message(
    federation_public_key: PublicKey,
    peer_id: PeerId,
    challenge: sha256::Hash,
) -> Message {
    let mut message_preimage = "remove-gateway".as_bytes().to_vec();
    message_preimage.append(&mut federation_public_key.consensus_encode_to_vec());
    let guardian_id: u16 = peer_id.into();
    message_preimage.append(&mut guardian_id.consensus_encode_to_vec());
    message_preimage.append(&mut challenge.consensus_encode_to_vec());
    Message::from_digest(*sha256::Hash::hash(message_preimage.as_slice()).as_ref())
}

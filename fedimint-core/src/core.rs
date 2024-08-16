//! Fedimint Core API (common) module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that is used on both client and sever side.
use core::fmt;
use std::any::{Any, TypeId};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;
use std::{cmp, marker};

use anyhow::anyhow;
use bitcoin_hashes::{sha256, Hash};
use fedimint_core::encoding::{Decodable, DecodeError, DynEncodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize};

use crate::module::registry::ModuleRegistry;
use crate::{
    erased_eq_no_instance_id, module_plugin_dyn_newtype_clone_passthrough,
    module_plugin_dyn_newtype_define, module_plugin_dyn_newtype_display_passthrough,
    module_plugin_dyn_newtype_encode_decode, module_plugin_dyn_newtype_eq_passthrough,
    module_plugin_static_trait_define, module_plugin_static_trait_define_config,
};

pub mod server;

pub mod backup;

/// Unique identifier for one semantic, correlatable operation.
///
/// The concept of *operations* is used to avoid losing privacy while being as
/// efficient as possible with regards to network requests.
///
/// For Fedimint transactions to be private users need to communicate with the
/// federation using an anonymous communication network. If each API request was
/// done in a way that it cannot be correlated to any other API request we would
/// achieve privacy, but would reduce efficiency. E.g. on Tor we would need to
/// open a new circuit for every request and open a new web socket connection.
///
/// Fortunately we do not need to do that to maintain privacy. Many API requests
/// and transactions can be correlated by the federation anyway, in these cases
/// it does not make any difference to re-use the same network connection. All
/// requests, transactions, state machines that are connected from the
/// federation's point of view anyway are grouped together as one *operation*.
///
/// # Choice of Operation ID
///
/// In cases where an operation is created by a new transaction that's being
/// submitted the transaction's ID can be used as operation ID. If there is no
/// transaction related to it, it should be generated randomly. Since it is a
/// 256bit value collisions are impossible for all intents and purposes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Encodable, Decodable, PartialOrd, Ord)]
pub struct OperationId(pub [u8; 32]);

pub struct OperationIdFullFmt<'a>(&'a OperationId);
pub struct OperationIdShortFmt<'a>(&'a OperationId);

impl OperationId {
    /// Generate random [`OperationId`]
    pub fn new_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_encodable<E: Encodable>(encodable: &E) -> Self {
        Self(encodable.consensus_hash::<sha256::Hash>().to_byte_array())
    }

    pub fn fmt_short(&self) -> OperationIdShortFmt {
        OperationIdShortFmt(self)
    }
    pub fn fmt_full(&self) -> OperationIdFullFmt {
        OperationIdFullFmt(self)
    }
}

impl<'a> Display for OperationIdShortFmt<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        bitcoin29::hashes::hex::format_hex(&self.0 .0[0..4], f)?;
        f.write_str("_")?;
        bitcoin29::hashes::hex::format_hex(&self.0 .0[28..], f)?;
        Ok(())
    }
}

impl<'a> Display for OperationIdFullFmt<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        bitcoin29::hashes::hex::format_hex(&self.0 .0, f)
    }
}

impl Debug for OperationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "OperationId({})", self.fmt_short())
    }
}

impl FromStr for OperationId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = hex::FromHex::from_hex(s)?;
        Ok(Self(bytes))
    }
}

impl Serialize for OperationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.fmt_full().to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let operation_id = Self::from_str(&s)
                .map_err(|e| serde::de::Error::custom(format!("invalid operation id: {e}")))?;
            Ok(operation_id)
        } else {
            let bytes: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

/// Module instance ID
///
/// This value uniquely identifies a single instance of a module in a
/// federation.
///
/// In case a single [`ModuleKind`] is instantiated twice (rare, but possible),
/// each instance will have a different id.
///
/// Note: We have used this type differently before, assuming each `u16`
/// uniquly identifies a type of module in question. This function will move
/// to a `ModuleKind` type which only identifies type of a module (mint vs
/// wallet vs ln, etc)
// TODO: turn in a newtype
pub type ModuleInstanceId = u16;

/// Special IDs we use for global dkg
pub const MODULE_INSTANCE_ID_GLOBAL: u16 = u16::MAX;

// Note: needs to be in alphabetical order of ModuleKind of each module,
// as this is the ordering we currently hardcoded.
// Should be used only for pre-modularization code we still have  left
pub const LEGACY_HARDCODED_INSTANCE_ID_LN: ModuleInstanceId = 0;
pub const LEGACY_HARDCODED_INSTANCE_ID_MINT: ModuleInstanceId = 1;
pub const LEGACY_HARDCODED_INSTANCE_ID_WALLET: ModuleInstanceId = 2;

/// A type of a module
///
/// This is a short string that identifies type of a module.
/// Authors of 3rd party modules are free to come up with a string,
/// long enough to avoid conflicts with similar modules.
#[derive(
    Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct ModuleKind(Cow<'static, str>);

impl ModuleKind {
    pub fn clone_from_str(s: &str) -> Self {
        Self(Cow::from(s.to_owned()))
    }

    pub const fn from_static_str(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<&'static str> for ModuleKind {
    fn from(val: &'static str) -> Self {
        Self::from_static_str(val)
    }
}

/// A type used by when decoding dyn-types, when the module is missing
///
/// This allows parsing and handling of dyn-types of modules which
/// are not available.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct DynUnknown(pub Vec<u8>);

impl fmt::Display for DynUnknown {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.consensus_encode_to_hex())
    }
}

// Note: confusingly, while `DynUnknown` carries a `Vec`
// it is actually not responsible for writing out the length of the data,
// as the higher level (`module_plugin_dyn_newtype_encode_decode`) is doing
// it, based on how many bytes are written here. That's why `DynUnknown` does
// not implement `Decodable` directly, and `Vec` here has len only
// for the purpose of knowing how many bytes to carry.
impl Encodable for DynUnknown {
    fn consensus_encode<W: std::io::Write>(&self, w: &mut W) -> Result<usize, std::io::Error> {
        w.write_all(&self.0[..])?;
        Ok(self.0.len())
    }
}

/// A type that has a `Dyn*`, type erased version of itself
///
/// Use [`IntoDynNever`] in places where a given type will never
/// actually be created, but something is needed to appease the
/// type system.
pub trait IntoDynInstance {
    /// The type erased version of the type implementing this trait
    type DynType: 'static;

    /// Convert `self` into its type-erased equivalent
    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType;
}

enum Never {}

/// Type that can be used as type-system placeholder for [`IntoDynInstance`]
pub struct IntoDynNever<T> {
    _phantom: marker::PhantomData<T>,
    // you can't make that
    _never: Never,
}

impl<T> cmp::PartialEq for IntoDynNever<T> {
    fn eq(&self, _: &Self) -> bool {
        unreachable!()
    }
}

impl<T> cmp::Eq for IntoDynNever<T> {}

impl<T> fmt::Debug for IntoDynNever<T> {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        unreachable!()
    }
}

impl<T> Clone for IntoDynNever<T> {
    fn clone(&self) -> Self {
        unreachable!()
    }
}

impl<T> Encodable for IntoDynNever<T> {
    fn consensus_encode<W: std::io::Write>(&self, _: &mut W) -> Result<usize, std::io::Error> {
        unreachable!()
    }
}

impl<T> Decodable for IntoDynNever<T> {
    fn consensus_decode<R: std::io::Read>(
        _: &mut R,
        _: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        unreachable!()
    }
}

impl<T> IntoDynInstance for IntoDynNever<T>
where
    T: 'static,
{
    type DynType = T;

    fn into_dyn(self, _instance_id: ModuleInstanceId) -> Self::DynType {
        unreachable!()
    }
}

type DecodeFn = Box<
    dyn for<'a> Fn(
            Box<dyn Read + 'a>,
            ModuleInstanceId,
            &ModuleDecoderRegistry,
        ) -> Result<Box<dyn Any>, DecodeError>
        + Send
        + Sync,
>;

#[derive(Default)]
pub struct DecoderBuilder {
    decode_fns: BTreeMap<TypeId, DecodeFn>,
    transparent: bool,
}

impl DecoderBuilder {
    pub fn build(self) -> Decoder {
        Decoder {
            decode_fns: Arc::new(self.decode_fns),
        }
    }

    /// Attach decoder for a specific `Type`/`DynType` pair where `DynType =
    /// <Type as IntoDynInstance>::DynType`.
    ///
    /// This allows calling `decode::<DynType>` on this decoder, returning a
    /// `DynType` object which contains a `Type` object internally.
    ///
    /// **Caution**: One `Decoder` object should only contain decoders that
    /// belong to the same [*module kind*](fedimint_core::core::ModuleKind).
    ///
    /// # Panics
    /// * If multiple `Types` with the same `DynType` are added
    pub fn with_decodable_type<Type>(&mut self)
    where
        Type: IntoDynInstance + Decodable,
    {
        let is_transparent_decoder = self.transparent;
        // TODO: enforce that all decoders are for the same module kind (+fix docs
        // after)
        let decode_fn: DecodeFn = Box::new(
            move |mut reader, instance, decoders: &ModuleDecoderRegistry| {
                // TODO: Ideally `DynTypes` decoding couldn't ever be nested, so we could just
                // pass empty `decoders`. But the client context uses nested `DynTypes` in
                // `DynState`, so we special-case it with a flag.
                let decoders = if is_transparent_decoder {
                    Cow::Borrowed(decoders)
                } else {
                    Cow::Owned(ModuleRegistry::default())
                };
                let typed_val = Type::consensus_decode(&mut reader, &decoders).map_err(|err| {
                    let err: anyhow::Error = err.into();
                    DecodeError::new_custom(
                        err.context(format!("while decoding Dyn type module_id={instance}")),
                    )
                })?;
                let dyn_val = typed_val.into_dyn(instance);
                let any_val: Box<dyn Any> = Box::new(dyn_val);
                Ok(any_val)
            },
        );
        if self
            .decode_fns
            .insert(TypeId::of::<Type::DynType>(), decode_fn)
            .is_some()
        {
            panic!("Tried to add multiple decoders for the same DynType");
        }
    }
}

/// Consensus encoding decoder for module-specific types
#[derive(Clone, Default)]
pub struct Decoder {
    decode_fns: Arc<BTreeMap<TypeId, DecodeFn>>,
}

impl Decoder {
    /// Creates a `DecoderBuilder` to which decoders for single types can be
    /// attached to build a `Decoder`.
    pub fn builder() -> DecoderBuilder {
        DecoderBuilder::default()
    }

    /// System Dyn-type, don't use.
    #[doc(hidden)]
    pub fn builder_system() -> DecoderBuilder {
        DecoderBuilder {
            transparent: true,
            ..DecoderBuilder::default()
        }
    }

    /// Decodes a specific `DynType` from the `reader` byte stream.
    ///
    /// # Panics
    /// * If no decoder is registered for the `DynType`
    pub fn decode_complete<DynType: Any>(
        &self,
        reader: &mut dyn Read,
        total_len: u64,
        module_id: ModuleInstanceId,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<DynType, DecodeError> {
        let mut reader = reader.take(total_len);

        let val = self.decode_partial(&mut reader, module_id, decoders)?;
        let left = reader.limit();

        if left != 0 {
            return Err(fedimint_core::encoding::DecodeError::new_custom(
                anyhow::anyhow!(
                    "Dyn type did not consume all bytes during decoding; module_id={}; expected={}; left={}; type={}",
                    module_id,
                    total_len,
                    left,
                    std::any::type_name::<DynType>(),
                ),
            ));
        }

        Ok(val)
    }

    /// Like [`Self::decode_complete`] but does not verify that all bytes were
    /// consumed
    pub fn decode_partial<DynType: Any>(
        &self,
        reader: &mut dyn Read,
        module_id: ModuleInstanceId,
        decoders: &ModuleDecoderRegistry,
    ) -> Result<DynType, DecodeError> {
        let decode_fn = self
            .decode_fns
            .get(&TypeId::of::<DynType>())
            .ok_or_else(|| {
                anyhow!(
                    "Type unknown to decoder: {}, (registered decoders={})",
                    std::any::type_name::<DynType>(),
                    self.decode_fns.len()
                )
            })
            .expect("Types being decoded must be registered");
        Ok(*decode_fn(Box::new(reader), module_id, decoders)?
            .downcast::<DynType>()
            .expect("Decode fn returned wrong type, can't happen due to with_decodable_type"))
    }
}

impl Debug for Decoder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Decoder(registered_types = {})", self.decode_fns.len())
    }
}

pub trait IClientConfig: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, instance_id: ModuleInstanceId) -> DynClientConfig;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynClientConfig) -> bool;
    fn to_json(&self) -> Option<serde_json::Value>;
}

module_plugin_static_trait_define_config! {
    DynClientConfig, ClientConfig, IClientConfig,
    { },
    {
        erased_eq_no_instance_id!(DynClientConfig);

        fn to_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::to_value(self.to_owned()).expect("serialization can't fail"))
        }
    },
    {
        erased_eq_no_instance_id!(DynClientConfig);

        fn to_json(&self) -> Option<serde_json::Value> {
            None
        }
    }
}

module_plugin_dyn_newtype_define! {
    /// An owned, immutable input to a [`Transaction`](fedimint_core::transaction::Transaction)
    pub DynClientConfig(Box<IClientConfig>)
}
module_plugin_dyn_newtype_encode_decode!(DynClientConfig);

module_plugin_dyn_newtype_clone_passthrough!(DynClientConfig);

module_plugin_dyn_newtype_eq_passthrough!(DynClientConfig);

module_plugin_dyn_newtype_display_passthrough!(DynClientConfig);

/// Something that can be an [`DynInput`] in a
/// [`Transaction`](fedimint_core::transaction::Transaction)
///
/// General purpose code should use [`DynInput`] instead
pub trait IInput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, instance_id: ModuleInstanceId) -> DynInput;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynInput) -> bool;
}

module_plugin_static_trait_define! {
    DynInput, Input, IInput,
    { },
    {
        erased_eq_no_instance_id!(DynInput);
    }
}

module_plugin_dyn_newtype_define! {
    /// An owned, immutable input to a [`Transaction`](fedimint_core::transaction::Transaction)
    pub DynInput(Box<IInput>)
}
module_plugin_dyn_newtype_encode_decode!(DynInput);

module_plugin_dyn_newtype_clone_passthrough!(DynInput);

module_plugin_dyn_newtype_eq_passthrough!(DynInput);

module_plugin_dyn_newtype_display_passthrough!(DynInput);

/// Something that can be an [`DynOutput`] in a
/// [`Transaction`](fedimint_core::transaction::Transaction)
///
/// General purpose code should use [`DynOutput`] instead
pub trait IOutput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, instance_id: ModuleInstanceId) -> DynOutput;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynOutput) -> bool;
}

module_plugin_dyn_newtype_define! {
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction)
    pub DynOutput(Box<IOutput>)
}
module_plugin_static_trait_define! {
    DynOutput, Output, IOutput,
    { },
    {
        erased_eq_no_instance_id!(DynOutput);
    }
}
module_plugin_dyn_newtype_encode_decode!(DynOutput);

module_plugin_dyn_newtype_clone_passthrough!(DynOutput);

module_plugin_dyn_newtype_eq_passthrough!(DynOutput);

module_plugin_dyn_newtype_display_passthrough!(DynOutput);

pub enum FinalizationError {
    SomethingWentWrong,
}

pub trait IOutputOutcome: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynOutputOutcome;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynOutputOutcome) -> bool;
}

module_plugin_dyn_newtype_define! {
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction) before it was finalized
    pub DynOutputOutcome(Box<IOutputOutcome>)
}
module_plugin_static_trait_define! {
    DynOutputOutcome, OutputOutcome, IOutputOutcome,
    { },
    {
        erased_eq_no_instance_id!(DynOutputOutcome);
    }
}
module_plugin_dyn_newtype_encode_decode!(DynOutputOutcome);
module_plugin_dyn_newtype_clone_passthrough!(DynOutputOutcome);
module_plugin_dyn_newtype_eq_passthrough!(DynOutputOutcome);
module_plugin_dyn_newtype_display_passthrough!(DynOutputOutcome);

pub trait IModuleConsensusItem: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynModuleConsensusItem;
    fn dyn_hash(&self) -> u64;

    fn erased_eq_no_instance_id(&self, other: &DynModuleConsensusItem) -> bool;
}

module_plugin_dyn_newtype_define! {
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction) before it was finalized
    pub DynModuleConsensusItem(Box<IModuleConsensusItem>)
}
module_plugin_static_trait_define! {
    DynModuleConsensusItem, ModuleConsensusItem, IModuleConsensusItem,
    { },
    {
        erased_eq_no_instance_id!(DynModuleConsensusItem);
    }
}
module_plugin_dyn_newtype_encode_decode!(DynModuleConsensusItem);

module_plugin_dyn_newtype_clone_passthrough!(DynModuleConsensusItem);

module_plugin_dyn_newtype_eq_passthrough!(DynModuleConsensusItem);

module_plugin_dyn_newtype_display_passthrough!(DynModuleConsensusItem);

pub trait IOutputError: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynOutputError;
    fn dyn_hash(&self) -> u64;

    fn erased_eq_no_instance_id(&self, other: &DynOutputError) -> bool;
}

module_plugin_dyn_newtype_define! {
    pub DynOutputError(Box<IOutputError>)
}
module_plugin_static_trait_define! {
    DynOutputError, OutputError, IOutputError,
    { },
    {
        erased_eq_no_instance_id!(DynOutputError);
    }
}
module_plugin_dyn_newtype_encode_decode!(DynOutputError);

module_plugin_dyn_newtype_clone_passthrough!(DynOutputError);

module_plugin_dyn_newtype_eq_passthrough!(DynOutputError);

module_plugin_dyn_newtype_display_passthrough!(DynOutputError);

pub trait IInputError: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn module_kind(&self) -> Option<ModuleKind>;
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynInputError;
    fn dyn_hash(&self) -> u64;

    fn erased_eq_no_instance_id(&self, other: &DynInputError) -> bool;
}

module_plugin_dyn_newtype_define! {
    pub DynInputError(Box<IInputError>)
}
module_plugin_static_trait_define! {
    DynInputError, InputError, IInputError,
    { },
    {
        erased_eq_no_instance_id!(DynInputError);
    }
}
module_plugin_dyn_newtype_encode_decode!(DynInputError);

module_plugin_dyn_newtype_clone_passthrough!(DynInputError);

module_plugin_dyn_newtype_eq_passthrough!(DynInputError);

module_plugin_dyn_newtype_display_passthrough!(DynInputError);

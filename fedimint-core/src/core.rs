//! Fedimint Core API (common) module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that is used on both client and sever side.
use core::fmt;
use std::any::Any;
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::{cmp, marker};

use fedimint_core::encoding::{Decodable, DecodeError, DynEncodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use serde::{Deserialize, Serialize};

use crate::{
    erased_eq_no_instance_id, module_plugin_dyn_newtype_clone_passthrough,
    module_plugin_dyn_newtype_define, module_plugin_dyn_newtype_display_passthrough,
    module_plugin_dyn_newtype_encode_decode, module_plugin_dyn_newtype_eq_passthrough,
    module_plugin_static_trait_define, module_plugin_static_trait_define_config,
};

pub mod server;

pub mod backup;

mod decoder;
mod operation_id;

pub use decoder::{Decoder, DecoderBuilder};
pub use operation_id::OperationId;

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

/// Type that can be used as type-system placeholder for [`IntoDynInstance`]
pub struct IntoDynNever<T> {
    _phantom: marker::PhantomData<T>,
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

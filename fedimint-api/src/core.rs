//! Fedimint Core API (common) module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that is used on both client and sever side.
use core::fmt;
use std::any::Any;
use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::io;
use std::io::Read;
use std::sync::Arc;

pub use bitcoin::KeyPair;
use fedimint_api::dyn_newtype_define;
use fedimint_api::encoding::{Decodable, DecodeError, DynEncodable, Encodable};
use serde::{Deserialize, Serialize};

use crate::{
    dyn_newtype_define_with_instance_id, dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id,
    ModuleDecoderRegistry,
};

pub mod encode;

pub mod client;
pub mod server;

/// Module instance ID
///
/// This value uniquely identifies a single instance of a module in a federation.
///
/// In case a single [`ModuleKind`] is instantiated twice (rare, but possible),
/// each instance will have a different id.
///
/// Note: We have used this type differently before, assuming each `u16`
/// uniquly identifies a type of module in question. This function will move
/// to a `ModuleKind` type which only identifies type of a module (mint vs wallet vs ln, etc)
// TODO: turn in a newtype
pub type ModuleInstanceId = u16;

/// Special ID we use for global dkg
pub const MODULE_INSTANCE_ID_GLOBAL: u16 = u16::MAX;

// Note: needs to be in alphabetical order of ModuleKind of each module,
// as this is the ordering we currently harcoded.
// Should be used only for pre-modularization code we still have  left
pub const LEGACY_HARDCODED_INSTANCE_ID_LN: ModuleInstanceId = 0;
pub const LEGACY_HARDCODED_INSTANCE_ID_MINT: ModuleInstanceId = 1;
pub const LEGACY_HARDCODED_INSTANCE_ID_WALLET: ModuleInstanceId = 2;

/// A type of a module
///
/// This is a short string that identifies type of a module.
/// Authors of 3rd party modules are free to come up with a string,
/// long enough to avoid conflicts with similar modules.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
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
        ModuleKind::from_static_str(val)
    }
}

/// Implement `Encodable` and `Decodable` for a "module dyn newtype"
///
/// "Module dyn newtype" is just a "dyn newtype" used by general purpose
/// Fedimint code to abstract away details of mint modules.
#[macro_export]
macro_rules! module_dyn_newtype_impl_encode_decode {
    (
        $name:ident, $decode_fn:ident
    ) => {
        impl Encodable for $name {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                self.1.consensus_encode(writer)?;
                self.0.consensus_encode_dyn(writer)
            }
        }

        impl Decodable for $name {
            fn consensus_decode<R: std::io::Read>(
                r: &mut R,
                modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, DecodeError> {
                $crate::core::encode::module_decode_key_prefixed_decodable(
                    r,
                    modules,
                    |r, m, id| m.$decode_fn(r, id),
                )
            }
        }
    };
}
/// Define a "plugin" trait
///
/// "Plugin trait" is a trait that a developer of a mint module
/// needs to implement when implementing mint module. It uses associated
/// types with trait bonds to guide the developer.
///
/// Blanket implementations are used to convert the "plugin trait",
/// incompatible with `dyn Trait` into "module types" and corresponding
/// "module dyn newtypes", erasing the exact type and used in a common
/// Fedimint code.
#[macro_export]
macro_rules! module_plugin_trait_define{
    (   $(#[$outer:meta])*
        $newtype_ty:ident, $plugin_ty:ident, $module_ty:ident, { $($extra_methods:tt)*  } { $($extra_impls:tt)* }
    ) => {
        pub trait $plugin_ty:
            std::fmt::Debug + std::fmt::Display + std::cmp::PartialEq + std::hash::Hash + DynEncodable + Decodable + Encodable + Clone + Send + Sync + 'static
        {
            $($extra_methods)*
        }

        impl<T> $module_ty for T
        where
            T: $plugin_ty + DynEncodable + 'static + Send + Sync,
        {
            fn as_any(&self) -> &(dyn Any + Send + Sync) {
                self
            }

            fn clone(&self, instance_id: ::fedimint_api::core::ModuleInstanceId) -> $newtype_ty {
                $newtype_ty::from_typed(instance_id, <Self as Clone>::clone(self))
            }

            fn dyn_hash(&self) -> u64 {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                self.hash(&mut s);
                std::hash::Hasher::finish(&s)
            }

            $($extra_impls)*
        }

        impl std::hash::Hash for $newtype_ty {
            fn hash<H>(&self, state: &mut H)
            where
                H: std::hash::Hasher
            {
                self.1.hash(state);
                self.0.dyn_hash().hash(state);
            }
        }
    };
}

/// Implements the necessary traits for all associated types of a `FederationServer` module.
#[macro_export]
macro_rules! plugin_types_trait_impl {
    ($key:expr, $input:ty, $output:ty, $outcome:ty, $ci:ty, $cache:ty) => {
        impl fedimint_api::core::Input for $input {}

        impl fedimint_api::core::Output for $output {}

        impl fedimint_api::core::OutputOutcome for $outcome {}

        impl fedimint_api::core::ModuleConsensusItem for $ci {}

        impl fedimint_api::server::VerificationCache for $cache {}
    };
}

macro_rules! erased_eq_no_instance_id {
    ($newtype:ty) => {
        fn erased_eq_no_instance_id(&self, other: &$newtype) -> bool {
            let other: &T = other
                .as_any()
                .downcast_ref()
                .expect("Type is ensured in previous step");

            self == other
        }
    };
}

macro_rules! newtype_impl_eq_passthrough_with_instance_id {
    ($newtype:ty) => {
        impl PartialEq for $newtype {
            fn eq(&self, other: &Self) -> bool {
                if self.1 != other.1 {
                    return false;
                }
                self.erased_eq_no_instance_id(other)
            }
        }

        impl Eq for $newtype {}
    };
}

/// Implementes the `Display` trait for dyn newtypes whose traits implement `Display`
macro_rules! newtype_impl_display_passthrough {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

macro_rules! newtype_impl_display_passthrough_with_instance_id {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}-{}", self.1, self.0))
            }
        }
    };
}

/// Module Decoder trait
///
/// Static-polymorphism version of [`IDecoder`]
///
/// All methods are static, as the decoding code is supposed to be instance-independent,
/// at least until we start to support modules with overriden [`ModuleInstanceId`]s
pub trait Decoder: Debug + Send + Sync + 'static {
    type Input: Input;
    type Output: Output;
    type OutputOutcome: OutputOutcome;
    type ConsensusItem: ModuleConsensusItem;

    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Self::Input, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Self::Output, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<Self::OutputOutcome, DecodeError>;

    /// Decode `ConsensusItem` compatible with this module, after the module key prefix was already decoded
    fn decode_consensus_item(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<Self::ConsensusItem, DecodeError>;
}

pub trait IDecoder: Debug {
    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynInput, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynOutput, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynOutputOutcome, DecodeError>;

    /// Decode `ConsensusItem` compatible with this module, after the module key prefix was already decoded
    fn decode_consensus_item(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynModuleConsensusItem, DecodeError>;
}

// TODO: use macro again
/// Decoder for module associated types
#[derive(Clone)]
pub struct DynDecoder(Arc<dyn IDecoder + Send + Sync>);

impl std::ops::Deref for DynDecoder {
    type Target = dyn IDecoder + Send + Sync + 'static;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &*self.0
    }
}

impl<T> From<T> for DynDecoder
where
    T: Decoder + Send + Sync + 'static,
{
    fn from(value: T) -> Self {
        DynDecoder(Arc::new(value))
    }
}

impl std::fmt::Debug for DynDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<T> IDecoder for T
where
    T: Decoder + 'static,
{
    fn decode_input(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynInput, DecodeError> {
        Ok(DynInput::from_typed(
            instance_id,
            <Self as Decoder>::decode_input(self, r)?,
        ))
    }

    fn decode_output(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynOutput, DecodeError> {
        Ok(DynOutput::from_typed(
            instance_id,
            <Self as Decoder>::decode_output(self, r)?,
        ))
    }

    fn decode_output_outcome(
        &self,
        r: &mut dyn Read,

        instance_id: ModuleInstanceId,
    ) -> Result<DynOutputOutcome, DecodeError> {
        Ok(DynOutputOutcome::from_typed(
            instance_id,
            <Self as Decoder>::decode_output_outcome(self, r)?,
        ))
    }

    fn decode_consensus_item(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynModuleConsensusItem, DecodeError> {
        Ok(DynModuleConsensusItem::from_typed(
            instance_id,
            <Self as Decoder>::decode_consensus_item(self, r)?,
        ))
    }
}

impl IDecoder for DynDecoder {
    fn decode_input(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynInput, DecodeError> {
        self.0.decode_input(r, instance_id)
    }

    fn decode_output(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynOutput, DecodeError> {
        self.0.decode_output(r, instance_id)
    }

    fn decode_output_outcome(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynOutputOutcome, DecodeError> {
        self.0.decode_output_outcome(r, instance_id)
    }

    fn decode_consensus_item(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<DynModuleConsensusItem, DecodeError> {
        self.0.decode_consensus_item(r, instance_id)
    }
}

impl DynDecoder {
    /// Create [`Self`] form a typed version defined by the plugin
    pub fn from_typed(decoder: impl Decoder + Send + Sync + 'static) -> DynDecoder {
        DynDecoder(Arc::new(decoder))
    }
}

/// Something that can be an [`DynInput`] in a [`Transaction`]
///
/// General purpose code should use [`DynInput`] instead
pub trait IInput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, instance_id: ModuleInstanceId) -> DynInput;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynInput) -> bool;
}

module_plugin_trait_define! {
    DynInput, Input, IInput,
    { }
    {
        erased_eq_no_instance_id!(DynInput);
    }
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable input to a [`Transaction`]
    pub DynInput(Box<IInput>)
}
module_dyn_newtype_impl_encode_decode! {
    DynInput, decode_input
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynInput);

newtype_impl_eq_passthrough_with_instance_id!(DynInput);

newtype_impl_display_passthrough_with_instance_id!(DynInput);

/// Something that can be an [`DynOutput`] in a [`Transaction`]
///
/// General purpose code should use [`DynOutput`] instead
pub trait IOutput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, instance_id: ModuleInstanceId) -> DynOutput;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynOutput) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`]
    pub DynOutput(Box<IOutput>)
}
module_plugin_trait_define! {
    DynOutput, Output, IOutput,
    { }
    {
        erased_eq_no_instance_id!(DynOutput);
    }
}
module_dyn_newtype_impl_encode_decode! {
    DynOutput, decode_output
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynOutput);

newtype_impl_eq_passthrough_with_instance_id!(DynOutput);

newtype_impl_display_passthrough_with_instance_id!(DynOutput);

pub enum FinalizationError {
    SomethingWentWrong,
}

pub trait IOutputOutcome: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynOutputOutcome;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynOutputOutcome) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    pub DynOutputOutcome(Box<IOutputOutcome>)
}
module_plugin_trait_define! {
    DynOutputOutcome, OutputOutcome, IOutputOutcome,
    { }
    {
        erased_eq_no_instance_id!(DynOutputOutcome);
    }
}
module_dyn_newtype_impl_encode_decode! {
    DynOutputOutcome, decode_output_outcome
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynOutputOutcome);

newtype_impl_eq_passthrough_with_instance_id!(DynOutputOutcome);

newtype_impl_display_passthrough!(DynOutputOutcome);

pub trait IModuleConsensusItem: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, module_instance_id: ModuleInstanceId) -> DynModuleConsensusItem;
    fn dyn_hash(&self) -> u64;

    fn erased_eq_no_instance_id(&self, other: &DynModuleConsensusItem) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    pub DynModuleConsensusItem(Box<IModuleConsensusItem>)
}
module_plugin_trait_define! {
    DynModuleConsensusItem, ModuleConsensusItem, IModuleConsensusItem,
    { }
    {
        erased_eq_no_instance_id!(DynModuleConsensusItem);
    }
}
module_dyn_newtype_impl_encode_decode! {
    DynModuleConsensusItem, decode_consensus_item
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynModuleConsensusItem);

newtype_impl_eq_passthrough_with_instance_id!(DynModuleConsensusItem);

newtype_impl_display_passthrough!(DynModuleConsensusItem);

#[derive(Encodable, Decodable)]
pub struct Signature;

/// Transaction that was already signed
#[derive(Encodable)]
pub struct Transaction {
    inputs: Vec<DynInput>,
    outputs: Vec<DynOutput>,
    signature: Signature,
}

impl Decodable for Transaction
where
    DynInput: Decodable,
    DynOutput: Decodable,
{
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            inputs: Decodable::consensus_decode(r, modules)?,
            outputs: Decodable::consensus_decode(r, modules)?,
            signature: Decodable::consensus_decode(r, modules)?,
        })
    }
}

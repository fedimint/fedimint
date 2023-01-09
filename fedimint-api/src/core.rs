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
use std::io::Read;
use std::sync::Arc;
use std::{io, ops};

pub use bitcoin::KeyPair;
use fedimint_api::{
    dyn_newtype_define,
    encoding::{Decodable, DecodeError, DynEncodable, Encodable},
};
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
/// long enough to avoid conflicts with similiar modules.
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

impl ops::Deref for ModuleKind {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
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
                (<Self as Clone>::clone(self), instance_id).into()
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

/// Implements the `Plugin*` traits for all associated types of a `FederationServerPlugin`.
#[macro_export]
macro_rules! plugin_types_trait_impl {
    ($key:expr, $input:ty, $output:ty, $outcome:ty, $ci:ty, $cache:ty) => {
        impl fedimint_api::core::PluginInput for $input {}

        impl fedimint_api::core::PluginOutput for $output {}

        impl fedimint_api::core::PluginOutputOutcome for $outcome {}

        impl fedimint_api::core::PluginConsensusItem for $ci {}

        impl fedimint_api::server::PluginVerificationCache for $cache {}
    };
}

macro_rules! erased_eq {
    ($newtype:ty) => {
        fn erased_eq(&self, other: &$newtype) -> bool {
            // TODO:?
            // if self.module_key() != other.module_key() {
            //     return false;
            // }

            let other: &T = other
                .as_any()
                .downcast_ref()
                .expect("Type is ensured in previous step");

            self == other
        }
    };
}

macro_rules! newtype_impl_eq_passthrough {
    ($newtype:ty) => {
        impl PartialEq for $newtype {
            fn eq(&self, other: &Self) -> bool {
                self.erased_eq(other)
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

/// Module Decoder trait
///
/// Static-polymorphism version of [`ModuleDecode`]
///
/// All methods are static, as the decoding code is supposed to be instance-independent,
/// at least until we start to support modules with overriden [`ModuleInstanceId`]s
pub trait PluginDecode: Debug + Send + Sync + 'static {
    type Input: PluginInput;
    type Output: PluginOutput;
    type OutputOutcome: PluginOutputOutcome;
    type ConsensusItem: PluginConsensusItem;

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

pub trait ModuleDecode: Debug {
    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Input, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Output, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<OutputOutcome, DecodeError>;

    /// Decode `ConsensusItem` compatible with this module, after the module key prefix was already decoded
    fn decode_consensus_item(
        &self,
        r: &mut dyn io::Read,
        instance_id: ModuleInstanceId,
    ) -> Result<ConsensusItem, DecodeError>;
}

// TODO: use macro again
/// Decoder for module associated types
#[derive(Clone)]
pub struct Decoder(Arc<dyn ModuleDecode + Send + Sync>);

impl std::ops::Deref for Decoder {
    type Target = dyn ModuleDecode + Send + Sync + 'static;

    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &*self.0
    }
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<T> ModuleDecode for T
where
    T: PluginDecode + 'static,
{
    fn decode_input(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Input, DecodeError> {
        Ok((<Self as PluginDecode>::decode_input(self, r)?, instance_id).into())
    }

    fn decode_output(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Output, DecodeError> {
        Ok((<Self as PluginDecode>::decode_output(self, r)?, instance_id).into())
    }

    fn decode_output_outcome(
        &self,
        r: &mut dyn Read,

        instance_id: ModuleInstanceId,
    ) -> Result<OutputOutcome, DecodeError> {
        Ok((
            <Self as PluginDecode>::decode_output_outcome(self, r)?,
            instance_id,
        )
            .into())
    }

    fn decode_consensus_item(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<ConsensusItem, DecodeError> {
        Ok((
            <Self as PluginDecode>::decode_consensus_item(self, r)?,
            instance_id,
        )
            .into())
    }
}

impl ModuleDecode for Decoder {
    fn decode_input(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Input, DecodeError> {
        self.0.decode_input(r, instance_id)
    }

    fn decode_output(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<Output, DecodeError> {
        self.0.decode_output(r, instance_id)
    }

    fn decode_output_outcome(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<OutputOutcome, DecodeError> {
        self.0.decode_output_outcome(r, instance_id)
    }

    fn decode_consensus_item(
        &self,
        r: &mut dyn Read,
        instance_id: ModuleInstanceId,
    ) -> Result<ConsensusItem, DecodeError> {
        self.0.decode_consensus_item(r, instance_id)
    }
}

impl Decoder {
    /// Creates a static, type-erased decoder. Only call this a limited amout of times since it uses
    /// `Box::leak` internally.
    pub fn from_typed(decoder: impl PluginDecode + Send + Sync + 'static) -> Decoder {
        Decoder(Arc::new(decoder))
    }
}

/// Something that can be an [`Input`] in a [`Transaction`]
///
/// General purpose code should use [`Input`] instead
pub trait ModuleInput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, instance_id: ModuleInstanceId) -> Input;
    fn dyn_hash(&self) -> u64;
    fn erased_eq(&self, other: &Input) -> bool;
}

module_plugin_trait_define! {
    Input, PluginInput, ModuleInput,
    { }
    {
        erased_eq!(Input);
    }
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable input to a [`Transaction`]
    pub Input(Box<ModuleInput>)
}
module_dyn_newtype_impl_encode_decode! {
    Input, decode_input
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(Input);

newtype_impl_eq_passthrough!(Input);

newtype_impl_display_passthrough!(Input);

/// Something that can be an [`Output`] in a [`Transaction`]
///
/// General purpose code should use [`Output`] instead
pub trait ModuleOutput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, instance_id: ModuleInstanceId) -> Output;
    fn dyn_hash(&self) -> u64;
    fn erased_eq(&self, other: &Output) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`]
    pub Output(Box<ModuleOutput>)
}
module_plugin_trait_define! {
    Output, PluginOutput, ModuleOutput,
    { }
    {
        erased_eq!(Output);
    }
}
module_dyn_newtype_impl_encode_decode! {
    Output, decode_output
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(Output);

newtype_impl_eq_passthrough!(Output);

newtype_impl_display_passthrough!(Output);

pub enum FinalizationError {
    SomethingWentWrong,
}

pub trait ModuleOutputOutcome: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, module_instance_id: ModuleInstanceId) -> OutputOutcome;
    fn dyn_hash(&self) -> u64;
    fn erased_eq(&self, other: &OutputOutcome) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    pub OutputOutcome(Box<ModuleOutputOutcome>)
}
module_plugin_trait_define! {
    OutputOutcome, PluginOutputOutcome, ModuleOutputOutcome,
    { }
    {
        erased_eq!(OutputOutcome);
    }
}
module_dyn_newtype_impl_encode_decode! {
    OutputOutcome, decode_output_outcome
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(OutputOutcome);

newtype_impl_eq_passthrough!(OutputOutcome);

newtype_impl_display_passthrough!(OutputOutcome);

pub trait ModuleConsensusItem: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, module_instance_id: ModuleInstanceId) -> ConsensusItem;
    fn dyn_hash(&self) -> u64;

    fn erased_eq(&self, other: &ConsensusItem) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    pub ConsensusItem(Box<ModuleConsensusItem>)
}
module_plugin_trait_define! {
    ConsensusItem, PluginConsensusItem, ModuleConsensusItem,
    { }
    {
        erased_eq!(ConsensusItem);
    }
}
module_dyn_newtype_impl_encode_decode! {
    ConsensusItem, decode_consensus_item
}
dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(ConsensusItem);

newtype_impl_eq_passthrough!(ConsensusItem);

newtype_impl_display_passthrough!(ConsensusItem);

#[derive(Encodable, Decodable)]
pub struct Signature;

/// Transaction that was already signed
#[derive(Encodable)]
pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    signature: Signature,
}

impl Decodable for Transaction
where
    Input: Decodable,
    Output: Decodable,
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

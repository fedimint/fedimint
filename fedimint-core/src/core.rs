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
use std::sync::Arc;

use anyhow::anyhow;
pub use bitcoin::KeyPair;
use fedimint_core::dyn_newtype_define;
use fedimint_core::encoding::{Decodable, DecodeError, DynEncodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use serde::{Deserialize, Serialize};

use crate::{
    dyn_newtype_define_with_instance_id, dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id,
};

pub mod client;
pub mod server;

pub mod backup;

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
        ModuleKind::from_static_str(val)
    }
}

/// Implement `Encodable` and `Decodable` for a "module dyn newtype"
///
/// "Module dyn newtype" is just a "dyn newtype" used by general purpose
/// Fedimint code to abstract away details of mint modules.
#[macro_export]
macro_rules! module_dyn_newtype_impl_encode_decode {
    ($name:ident) => {
        impl Encodable for $name {
            fn consensus_encode<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, std::io::Error> {
                let mut written = self.module_instance_id.consensus_encode(writer)?;

                let mut buf = Vec::with_capacity(512);
                let buf_written = self.inner.consensus_encode_dyn(&mut buf)?;
                assert_eq!(buf.len(), buf_written);

                let buf_len_u32 = u32::try_from(buf.len())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                written += buf_len_u32.consensus_encode(writer)?;

                writer.write_all(buf.as_slice())?;
                written += buf.len();

                Ok(written)
            }
        }

        impl Decodable for $name {
            fn consensus_decode<R: std::io::Read>(
                reader: &mut R,
                modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, fedimint_core::encoding::DecodeError> {
                let module_instance_id =
                    fedimint_core::core::ModuleInstanceId::consensus_decode(reader, modules)?;
                let total_len = u32::consensus_decode(reader, modules)? as usize;
                let mut buf = Vec::with_capacity(512);
                while buf.len() < total_len {
                    let prev_len = buf.len();
                    let new_len = std::cmp::min(total_len, prev_len.saturating_add(512));
                    buf.resize(new_len, 0u8);
                    reader
                        .read_exact(&mut buf[prev_len..])
                        .map_err(|e| fedimint_core::encoding::DecodeError::new_custom(e.into()))?;
                }
                modules.get_expect(module_instance_id).decode(
                    &mut &buf[..],
                    module_instance_id,
                    modules,
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
            std::fmt::Debug + std::fmt::Display + std::cmp::PartialEq + std::hash::Hash + DynEncodable + Decodable + Encodable + Clone + IntoDynInstance<DynType = $newtype_ty> + Send + Sync + 'static
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

            fn clone(&self, instance_id: ::fedimint_core::core::ModuleInstanceId) -> $newtype_ty {
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
                self.module_instance_id.hash(state);
                self.inner.dyn_hash().hash(state);
            }
        }
    };
}

/// Implements the necessary traits for all configuration related types of a
/// `FederationServer` module.
#[macro_export]
macro_rules! plugin_types_trait_impl_config {
    ($common_gen:ty, $gen:ty, $gen_local:ty, $gen_consensus:ty, $cfg:ty, $cfg_local:ty, $cfg_private:ty, $cfg_consensus:ty, $cfg_client:ty) => {
        impl fedimint_core::config::ModuleGenParams for $gen {
            type Local = $gen_local;
            type Consensus = $gen_consensus;

            fn from_parts(local: Self::Local, consensus: Self::Consensus) -> Self {
                Self { local, consensus }
            }

            fn to_parts(self) -> (Self::Local, Self::Consensus) {
                (self.local, self.consensus)
            }
        }

        impl fedimint_core::config::TypedServerModuleConsensusConfig for $cfg_consensus {
            fn kind(&self) -> fedimint_core::core::ModuleKind {
                <$common_gen as fedimint_core::module::CommonModuleGen>::KIND
            }

            fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
                <$common_gen as fedimint_core::module::CommonModuleGen>::CONSENSUS_VERSION
            }
        }

        impl fedimint_core::config::TypedServerModuleConfig for $cfg {
            type Local = $cfg_local;
            type Private = $cfg_private;
            type Consensus = $cfg_consensus;

            fn from_parts(
                local: Self::Local,
                private: Self::Private,
                consensus: Self::Consensus,
            ) -> Self {
                Self {
                    local,
                    private,
                    consensus,
                }
            }

            fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
                (
                    <$common_gen as fedimint_core::module::CommonModuleGen>::KIND,
                    self.local,
                    self.private,
                    self.consensus,
                )
            }
        }

        impl fedimint_core::config::TypedClientModuleConfig for $cfg_client {
            fn kind(&self) -> fedimint_core::core::ModuleKind {
                <$common_gen as fedimint_core::module::CommonModuleGen>::KIND
            }

            fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
                <$common_gen as fedimint_core::module::CommonModuleGen>::CONSENSUS_VERSION
            }
        }
    };
}

/// Implements the necessary traits for all associated types of a
/// `FederationServer` module.
#[macro_export]
macro_rules! plugin_types_trait_impl_common {
    ($types:ty, $input:ty, $output:ty, $outcome:ty, $ci:ty) => {
        impl fedimint_core::module::ModuleCommon for $types {
            type Input = $input;
            type Output = $output;
            type OutputOutcome = $outcome;
            type ConsensusItem = $ci;
        }

        impl fedimint_core::core::Input for $input {}

        impl fedimint_core::core::IntoDynInstance for $input {
            type DynType = fedimint_core::core::DynInput;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynInput::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::Output for $output {}

        impl fedimint_core::core::IntoDynInstance for $output {
            type DynType = fedimint_core::core::DynOutput;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynOutput::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::OutputOutcome for $outcome {}

        impl fedimint_core::core::IntoDynInstance for $outcome {
            type DynType = fedimint_core::core::DynOutputOutcome;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynOutputOutcome::from_typed(instance_id, self)
            }
        }

        impl fedimint_core::core::ModuleConsensusItem for $ci {}

        impl fedimint_core::core::IntoDynInstance for $ci {
            type DynType = fedimint_core::core::DynModuleConsensusItem;

            fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
                fedimint_core::core::DynModuleConsensusItem::from_typed(instance_id, self)
            }
        }
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

#[macro_export]
macro_rules! newtype_impl_eq_passthrough_with_instance_id {
    ($newtype:ty) => {
        impl PartialEq for $newtype {
            fn eq(&self, other: &Self) -> bool {
                if self.module_instance_id != other.module_instance_id {
                    return false;
                }
                self.erased_eq_no_instance_id(other)
            }
        }

        impl Eq for $newtype {}
    };
}

/// Implements the `Display` trait for dyn newtypes whose traits implement
/// `Display`
macro_rules! newtype_impl_display_passthrough {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.inner, f)
            }
        }
    };
}

macro_rules! newtype_impl_display_passthrough_with_instance_id {
    ($newtype:ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}-{}", self.module_instance_id, self.inner))
            }
        }
    };
}

/// A type that has a `Dyn*`, type erased version of itself
pub trait IntoDynInstance {
    /// The type erased version of the type implementing this trait
    type DynType: 'static;

    /// Convert `self` into its type-erased equivalent
    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType;
}

type DecodeFn = for<'a> fn(
    Box<dyn Read + 'a>,
    ModuleInstanceId,
    &ModuleDecoderRegistry,
) -> Result<Box<dyn Any>, DecodeError>;

#[derive(Default)]
pub struct DecoderBuilder {
    decode_fns: BTreeMap<TypeId, DecodeFn>,
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
        // TODO: enforce that all decoders are for the same module kind (+fix docs
        // after)
        let decode_fn: DecodeFn = |mut reader, instance, modules| {
            let typed_val = Type::consensus_decode(&mut reader, modules)?;
            let dyn_val = typed_val.into_dyn(instance);
            let any_val: Box<dyn Any> = Box::new(dyn_val);
            Ok(any_val)
        };
        if self
            .decode_fns
            .insert(TypeId::of::<Type::DynType>(), decode_fn)
            .is_some()
        {
            panic!("Tried to add multiple decoders for the same DynType");
        }
    }
}

/// Decoder for module associated types
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

    /// Decodes a specific `DynType` from the `reader` byte stream.
    ///
    /// # Panics
    /// * If no decoder is registered for the `DynType`
    pub fn decode<DynType: Any>(
        &self,
        reader: &mut dyn Read,
        instance_id: ModuleInstanceId,
        modules: &ModuleDecoderRegistry,
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
        Ok(*decode_fn(Box::new(reader), instance_id, modules)?
            .downcast::<DynType>()
            .expect("Decode fn returned wrong type, can't happen due to with_decodable_type"))
    }
}

impl Debug for Decoder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Decoder(registered_types = {})", self.decode_fns.len())
    }
}

/// Something that can be an [`DynInput`] in a
/// [`Transaction`](fedimint_core::transaction::Transaction)
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
    /// An owned, immutable input to a [`Transaction`](fedimint_core::transaction::Transaction)
    pub DynInput(Box<IInput>)
}
module_dyn_newtype_impl_encode_decode!(DynInput);

dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynInput);

newtype_impl_eq_passthrough_with_instance_id!(DynInput);

newtype_impl_display_passthrough_with_instance_id!(DynInput);

/// Something that can be an [`DynOutput`] in a
/// [`Transaction`](fedimint_core::transaction::Transaction)
///
/// General purpose code should use [`DynOutput`] instead
pub trait IOutput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + Send + Sync);
    fn clone(&self, instance_id: ModuleInstanceId) -> DynOutput;
    fn dyn_hash(&self) -> u64;
    fn erased_eq_no_instance_id(&self, other: &DynOutput) -> bool;
}

dyn_newtype_define_with_instance_id! {
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction)
    pub DynOutput(Box<IOutput>)
}
module_plugin_trait_define! {
    DynOutput, Output, IOutput,
    { }
    {
        erased_eq_no_instance_id!(DynOutput);
    }
}
module_dyn_newtype_impl_encode_decode!(DynOutput);

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
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction) before it was finalized
    pub DynOutputOutcome(Box<IOutputOutcome>)
}
module_plugin_trait_define! {
    DynOutputOutcome, OutputOutcome, IOutputOutcome,
    { }
    {
        erased_eq_no_instance_id!(DynOutputOutcome);
    }
}
module_dyn_newtype_impl_encode_decode!(DynOutputOutcome);
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
    /// An owned, immutable output of a [`Transaction`](fedimint_core::transaction::Transaction) before it was finalized
    pub DynModuleConsensusItem(Box<IModuleConsensusItem>)
}
module_plugin_trait_define! {
    DynModuleConsensusItem, ModuleConsensusItem, IModuleConsensusItem,
    { }
    {
        erased_eq_no_instance_id!(DynModuleConsensusItem);
    }
}
module_dyn_newtype_impl_encode_decode!(DynModuleConsensusItem);

dyn_newtype_impl_dyn_clone_passhthrough_with_instance_id!(DynModuleConsensusItem);

newtype_impl_eq_passthrough_with_instance_id!(DynModuleConsensusItem);

newtype_impl_display_passthrough!(DynModuleConsensusItem);

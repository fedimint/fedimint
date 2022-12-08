//! Fedimint Core API (common) module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that is used on both client and sever side.
use std::any::Any;
use std::fmt::{Debug, Display};
use std::io;
use std::io::Read;
use std::sync::Arc;

pub use bitcoin::KeyPair;
use fedimint_api::{
    dyn_newtype_define, dyn_newtype_impl_dyn_clone_passhthrough,
    encoding::{Decodable, DecodeError, DynEncodable, Encodable},
};

use crate::ModuleDecoderRegistry;

pub mod encode;

pub mod client;
pub mod server;

/// A module key identifing a module
///
/// Used as an unique ID, and also as prefix in serialization
/// of module-specific data.
pub type ModuleKey = u16;

/// Temporary constant for the modules we already have
///
/// To be removed after modularization is complete.
pub const MODULE_KEY_WALLET: u16 = 0;
pub const MODULE_KEY_MINT: u16 = 1;
pub const MODULE_KEY_LN: u16 = 2;
// not really a module
pub const MODULE_KEY_GLOBAL: u16 = 1024;

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
                self.0.module_key().consensus_encode(writer)?;
                self.0.consensus_encode_dyn(writer)
            }
        }

        impl Decodable for $name {
            fn consensus_decode<R: std::io::Read>(
                r: &mut R,
                modules: &$crate::module::registry::ModuleDecoderRegistry,
            ) -> Result<Self, DecodeError> {
                $crate::core::encode::module_decode_key_prefixed_decodable(r, modules, |r, m| {
                    m.$decode_fn(r)
                })
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
macro_rules! module_plugin_trait_define {
    (   $(#[$outer:meta])*
        $newtype_ty:ident, $plugin_ty:ident, $module_ty:ident, { $($extra_methods:tt)*  } { $($extra_impls:tt)* }
    ) => {
        pub trait $plugin_ty:
            std::fmt::Debug + std::fmt::Display + std::cmp::PartialEq + std::hash::Hash + DynEncodable + Decodable + Encodable + Clone + Send + Sync + 'static
        {
            fn module_key(&self) -> ModuleKey;

            $($extra_methods)*
        }

        impl<T> $module_ty for T
        where
            T: $plugin_ty + DynEncodable + 'static + Send + Sync,
        {
            fn as_any(&self) -> &(dyn Any + 'static + Send + Sync) {
                self
            }

            fn module_key(&self) -> ModuleKey {
                <Self as $plugin_ty>::module_key(self)
            }

            fn clone(&self) -> $newtype_ty {
                <Self as Clone>::clone(self).into()
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
                let module_key = self.module_key();
                module_key.hash(state);
                self.0.dyn_hash().hash(state);
            }
        }
    };
}

/// Implements the `Plugin*` traits for all associated types of a `FederationServerPlugin`.
#[macro_export]
macro_rules! plugin_types_trait_impl {
    ($key:expr, $input:ty, $output:ty, $outcome:ty, $ci:ty, $cache:ty) => {
        impl fedimint_api::core::PluginInput for $input {
            fn module_key(&self) -> ModuleKey {
                $key
            }
        }

        impl fedimint_api::core::PluginOutput for $output {
            fn module_key(&self) -> ModuleKey {
                $key
            }
        }

        impl fedimint_api::core::PluginOutputOutcome for $outcome {
            fn module_key(&self) -> ModuleKey {
                $key
            }
        }

        impl fedimint_api::core::PluginConsensusItem for $ci {
            fn module_key(&self) -> ModuleKey {
                $key
            }
        }

        impl fedimint_api::server::PluginVerificationCache for $cache {
            fn module_key(&self) -> ModuleKey {
                $key
            }
        }
    };
}

macro_rules! erased_eq {
    ($newtype:ty) => {
        fn erased_eq(&self, other: &$newtype) -> bool {
            if self.module_key() != other.module_key() {
                return false;
            }

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
/// at least until we start to support modules with overriden [`ModuleKey`]s
pub trait PluginDecode: Debug {
    fn clone_decoder() -> Decoder;

    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    /// Decode `ConsensusItem` compatible with this module, after the module key prefix was already decoded
    fn decode_consensus_item(r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError>;
}

pub trait ModuleDecode: Debug {
    fn clone_decoder(&self) -> Decoder;

    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    /// Decode `ConsensusItem` compatible with this module, after the module key prefix was already decoded
    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError>;
}

// TODO: use macro again
#[doc = " Decoder for module associated types"]
pub struct Decoder(Arc<dyn ModuleDecode + Send + Sync + 'static>);

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

impl Clone for Decoder {
    fn clone(&self) -> Self {
        self.clone_decoder()
    }
}

impl<T> ModuleDecode for T
where
    T: PluginDecode + 'static,
{
    fn clone_decoder(&self) -> Decoder {
        <Self as PluginDecode>::clone_decoder()
    }

    fn decode_input(&self, r: &mut dyn Read) -> Result<Input, DecodeError> {
        <Self as PluginDecode>::decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn Read) -> Result<Output, DecodeError> {
        <Self as PluginDecode>::decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn Read) -> Result<OutputOutcome, DecodeError> {
        <Self as PluginDecode>::decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn Read) -> Result<ConsensusItem, DecodeError> {
        <Self as PluginDecode>::decode_consensus_item(r)
    }
}

impl ModuleDecode for Decoder {
    fn clone_decoder(&self) -> Decoder {
        self.0.clone_decoder()
    }

    fn decode_input(&self, r: &mut dyn Read) -> Result<Input, DecodeError> {
        self.0.decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn Read) -> Result<Output, DecodeError> {
        self.0.decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn Read) -> Result<OutputOutcome, DecodeError> {
        self.0.decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn Read) -> Result<ConsensusItem, DecodeError> {
        self.0.decode_consensus_item(r)
    }
}

impl Decoder {
    pub fn from_typed(decoder: impl PluginDecode + Send + Sync + 'static) -> Decoder {
        Decoder(Arc::new(decoder))
    }
}

/// Something that can be an [`Input`] in a [`Transaction`]
///
/// General purpose code should use [`Input`] instead
pub trait ModuleInput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static + Send + Sync);
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> Input;
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

dyn_newtype_define! {
    /// An owned, immutable input to a [`Transaction`]
    pub Input(Box<ModuleInput>)
}
module_dyn_newtype_impl_encode_decode! {
    Input, decode_input
}
dyn_newtype_impl_dyn_clone_passhthrough!(Input);

newtype_impl_eq_passthrough!(Input);

newtype_impl_display_passthrough!(Input);

/// Something that can be an [`Output`] in a [`Transaction`]
///
/// General purpose code should use [`Output`] instead
pub trait ModuleOutput: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static + Send + Sync);
    fn module_key(&self) -> ModuleKey;

    fn clone(&self) -> Output;
    fn dyn_hash(&self) -> u64;
    fn erased_eq(&self, other: &Output) -> bool;
}

dyn_newtype_define! {
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
dyn_newtype_impl_dyn_clone_passhthrough!(Output);

newtype_impl_eq_passthrough!(Output);

newtype_impl_display_passthrough!(Output);

pub enum FinalizationError {
    SomethingWentWrong,
}

pub trait ModuleOutputOutcome: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static + Send + Sync);
    /// Module key
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> OutputOutcome;
    fn dyn_hash(&self) -> u64;
    fn erased_eq(&self, other: &OutputOutcome) -> bool;
}

dyn_newtype_define! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    pub OutputOutcome(Box<ModuleOutputOutcome>)
}
module_plugin_trait_define! {
    OutputOutcome, PluginOutputOutcome, ModuleOutputOutcome,
    { }
    {
        fn erased_eq(&self, other: &OutputOutcome) -> bool {
            if self.module_key() != other.module_key() {
                return false;
            }

            let other = other
                .as_any()
                .downcast_ref::<T>()
                .expect("Type is ensured in previous step");

            self == other
        }
    }
}
module_dyn_newtype_impl_encode_decode! {
    OutputOutcome, decode_output_outcome
}
dyn_newtype_impl_dyn_clone_passhthrough!(OutputOutcome);

newtype_impl_eq_passthrough!(OutputOutcome);

newtype_impl_display_passthrough!(OutputOutcome);

pub trait ModuleConsensusItem: Debug + Display + DynEncodable {
    fn as_any(&self) -> &(dyn Any + 'static + Send + Sync);
    /// Module key
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> ConsensusItem;
    fn dyn_hash(&self) -> u64;

    fn erased_eq(&self, other: &ConsensusItem) -> bool;
}

dyn_newtype_define! {
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
dyn_newtype_impl_dyn_clone_passhthrough!(ConsensusItem);

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

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use fedimint_api::core::PluginConsensusItem;
    use fedimint_api::encoding::{Decodable, Encodable};

    use crate::core::{
        ConsensusItem, Input, ModuleKey, Output, OutputOutcome, PluginInput, PluginOutput,
        PluginOutputOutcome,
    };

    macro_rules! test_newtype_eq_hash {
        ($newtype:ty, $trait:ty) => {
            #[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
            struct Foo {
                key: u16,
                data: u16,
            }

            impl std::fmt::Display for Foo {
                fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    unimplemented!();
                }
            }

            impl $trait for Foo {
                fn module_key(&self) -> ModuleKey {
                    self.key
                }
            }

            let a: $newtype = Foo { key: 42, data: 0 }.into();
            let b: $newtype = Foo { key: 21, data: 0 }.into();
            let c: $newtype = Foo { key: 42, data: 1 }.into();

            assert_eq!(a, a);
            assert_ne!(a, b);
            assert_ne!(a, c);
            assert_ne!(b, c);

            assert_eq!(hash(&a), hash(&a));
            assert_ne!(hash(&a), hash(&b));
            assert_ne!(hash(&a), hash(&c));
            assert_ne!(hash(&b), hash(&c));
        };
    }

    fn hash<T>(item: &T) -> u64
    where
        T: Hash,
    {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_dyn_eq_hash_input() {
        test_newtype_eq_hash!(Input, PluginInput);
    }

    #[test]
    fn test_dyn_eq_hash_output() {
        test_newtype_eq_hash!(Output, PluginOutput);
    }

    #[test]
    fn test_dyn_eq_hash_outcome() {
        test_newtype_eq_hash!(OutputOutcome, PluginOutputOutcome);
    }

    #[test]
    fn test_dyn_eq_hash_ci() {
        test_newtype_eq_hash!(ConsensusItem, PluginConsensusItem);
    }
}

//! Fedimint Core API (common) module interface
//!
//! Fedimint supports externally implemented modules.
//!
//! This (Rust) module defines common interoperability types
//! and functionality that is used on both client and sever side.
use crate::encode::{module_decode_key_prefixed_decodable, ModuleDecodable};
use fedimint_api::{
    encoding::{Decodable, DecodeError, DynEncodable, Encodable},
    Amount,
};
use impl_tools::autoimpl;
use std::io;
use std::{any::Any, collections::BTreeMap};

pub use bitcoin::KeyPair;
pub mod encode;

pub mod client;
pub mod server;

/// A module key identifing a module
///
/// Used as an unique ID, and also as prefix in serialization
/// of module-specific data.
pub type ModuleKey = u16;

#[macro_export]
macro_rules! def_module_type_newtype {
    (   $(#[$outer:meta])*
        $name:ident($container:ident<$trait:ident>)
    ) => {
        #[autoimpl(Deref using self.0)]
        $(#[$outer])*
        pub struct $name($container<dyn $trait + Send + Sync + 'static>);

        impl<I> From<I> for $name
        where
            I: $trait + Send + Sync + 'static,
        {
            fn from(i: I) -> Self {
                Self($container::new(i))
            }
        }

    }
}

#[macro_export]
macro_rules! impl_module_type_newtype_encode {
    (
        $name:ident, $decode_fn:ident
    ) => {
        impl Encodable for $name {
            fn consensus_encode<W: std::io::Write>(
                &self,
                mut writer: W,
            ) -> Result<usize, std::io::Error> {
                self.0.module_key().consensus_encode(&mut writer)?;
                self.0.consensus_encode_dyn(&mut writer)
            }
        }

        impl<M> ModuleDecodable<M> for $name
        where
            M: ModuleCommon,
        {
            fn consensus_decode<R: std::io::Read>(
                mut r: &mut R,
                modules: &BTreeMap<ModuleKey, M>,
            ) -> Result<Self, DecodeError> {
                module_decode_key_prefixed_decodable(&mut r, modules, |r, m| m.$decode_fn(r))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_module_type_newtype_clone {
    (
        $name:ident
    ) => {
        impl Clone for $name {
            fn clone(&self) -> Self {
                self.0.clone()
            }
        }
    };
}

#[macro_export]
macro_rules! def_module_type_plugin_type {
    (   $(#[$outer:meta])*
        $newtype_ty:ident, $plugin_ty:ident, $module_ty:ident, { $($extra_methods:tt)*  } { $($extra_impls:tt)* }
    ) => {
        pub trait $plugin_ty:
            DynEncodable + Decodable + Encodable + Clone + Send + Sync + 'static
        {
            fn module_key(&self) -> ModuleKey;

            $($extra_methods)*
        }

        impl<T> $module_ty for T
        where
            T: $plugin_ty + DynEncodable + 'static,
        {
            fn as_any(&self) -> &(dyn Any + '_) {
                self
            }

            fn module_key(&self) -> ModuleKey {
                <Self as $plugin_ty>::module_key(self)
            }

            fn clone(&self) -> $newtype_ty {
                <Self as Clone>::clone(self).into()
            }

            $($extra_impls)*
        }
    };
}

/// Common functionality of a Fedimint module
///
/// Both backend and server part of the module will need
/// things like decoding module-specific data.
pub trait ModuleCommon {
    fn module_key(&self) -> ModuleKey;

    /// Decode `SpendableOutput` compatible with this module, after the module key prefix was already decoded
    fn decode_spendable_output(&self, r: &mut dyn io::Read)
        -> Result<SpendableOutput, DecodeError>;

    /// Decode `Input` compatible with this module, after the module key prefix was already decoded
    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    /// Decode `Output` compatible with this module, after the module key prefix was already decoded
    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    /// Decode `PendingOutput` compatible with this module, after the module key prefix was already decoded
    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError>;

    /// Decode `OutputOutcome` compatible with this module, after the module key prefix was already decoded
    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;
}

/// Something that can be an [`Input`] in a [`Transaction`]
///
/// General purpose code should use [`Input`] instead
pub trait ModuleInput: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    fn module_key(&self) -> ModuleKey;
    fn amount(&self) -> Amount;
    fn clone(&self) -> Input;
}

def_module_type_plugin_type! {
    Input, PluginInput, ModuleInput,
    {
        fn amount(&self) -> Amount;
    }
    {
        fn amount(&self) -> Amount {
            <Self as PluginInput>::amount(self)
        }
    }
}

def_module_type_newtype! {
    /// An owned, immutable input to a [`Transaction`]
    Input(Box<ModuleInput>)
}
impl_module_type_newtype_encode! {
    Input, decode_input
}
impl_module_type_newtype_clone!(Input);

/// Something that can be an [`Output`] in a [`Transaction`]
///
/// General purpose code should use [`Output`] instead
pub trait ModuleOutput: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    fn module_key(&self) -> ModuleKey;
    fn amount(&self) -> Amount;

    fn clone(&self) -> Output;
}

def_module_type_newtype! {
    /// An owned, immutable output of a [`Transaction`]
    Output(Box<ModuleOutput>)
}
def_module_type_plugin_type! {
    Output, PluginOutput, ModuleOutput,
    {
        fn amount(&self) -> Amount;
    }
    {
        fn amount(&self) -> Amount {
            <Self as PluginOutput>::amount(self)
        }
    }
}
impl_module_type_newtype_encode! {
    Output, decode_output
}
impl_module_type_newtype_clone!(Output);

/// A spendable output - tracked and persisted by the client
///
/// Created by generating transaction [`Output`], spendable
/// by converting to [`Input`].
pub trait ModuleSpendableOutput: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    /// Module key
    fn module_key(&self) -> ModuleKey;
    fn amount(&self) -> Amount;
    fn clone(&self) -> SpendableOutput;

    // TODO: move to be module function
    /// Prepare [`Input`] spending thish output in a transaction, and a key used to sign the [`Transaction`]
    // fn to_input(&self) -> (Input, KeyPair);

    fn key(&self) -> String;
}

def_module_type_newtype! {
    /// An owned, immutable output of a [`Transaction`] after it was finalized (so it's spendable)
    SpendableOutput(Box<ModuleSpendableOutput>)
}
def_module_type_plugin_type! {
    SpendableOutput, PluginSpendableOutput, ModuleSpendableOutput,
    {
        fn amount(&self) -> Amount;
        fn key(&self) -> String;
    }
    {
        fn amount(&self) -> Amount {
            <Self as PluginSpendableOutput>::amount(self)
        }
        fn key(&self) -> String {
            <Self as PluginSpendableOutput>::key(self)
        }
    }
}
impl_module_type_newtype_encode! {
    SpendableOutput, decode_spendable_output
}
impl_module_type_newtype_clone!(SpendableOutput);

pub enum FinalizationError {
    SomethingWentWrong,
}

/// A pending output - tracked and persisted by the client
///
/// Created by generating transaction [`Output`], spendable
/// by converting to [`Input`].
pub trait ModulePendingOutput: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    /// Module key
    fn module_key(&self) -> ModuleKey;
    fn amount(&self) -> Amount;
    fn clone(&self) -> PendingOutput;

    // fn key(&self) -> String;
}

def_module_type_newtype! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    PendingOutput(Box<ModulePendingOutput>)
}
def_module_type_plugin_type! {
    PendingOutput, PluginPendingOutput, ModulePendingOutput,
    {
        fn amount(&self) -> Amount;
    }
    {
        fn amount(&self) -> Amount {
            <Self as PluginPendingOutput>::amount(self)
        }
    }
}
impl_module_type_newtype_encode! {
    PendingOutput, decode_pending_output
}
impl_module_type_newtype_clone!(PendingOutput);

pub trait ModuleOutputOutcome: DynEncodable {
    fn as_any(&self) -> &(dyn Any + '_);
    /// Module key
    fn module_key(&self) -> ModuleKey;
    fn clone(&self) -> OutputOutcome;
}

def_module_type_newtype! {
    /// An owned, immutable output of a [`Transaction`] before it was finalized
    OutputOutcome(Box<ModuleOutputOutcome>)
}
def_module_type_plugin_type! {
    OutputOutcome, PluginOutputOutcome, ModuleOutputOutcome,
    { }
    { }
}
impl_module_type_newtype_encode! {
    OutputOutcome, decode_output_outcome
}
impl_module_type_newtype_clone!(OutputOutcome);

#[derive(Encodable, Decodable)]
pub struct Signature;

/// Transaction that was already signed
#[derive(Encodable)]
pub struct Transaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    signature: Signature,
}

impl<M> ModuleDecodable<M> for Transaction
where
    Input: ModuleDecodable<M>,
    Output: ModuleDecodable<M>,
{
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &BTreeMap<ModuleKey, M>,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            inputs: ModuleDecodable::consensus_decode(r, modules)?,
            outputs: ModuleDecodable::consensus_decode(r, modules)?,
            signature: Decodable::consensus_decode(r)?,
        })
    }
}

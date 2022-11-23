use std::any::Any;
use std::fmt::Debug;
use std::io;
use std::io::Read;
use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{ConsensusItem, Input, Output, OutputOutcome};
use crate::core::{ModuleKey, PluginDecode};
use crate::module::TransactionItemAmount;
use crate::{dyn_newtype_define, DecodeError, ModuleDecode, ServerModulePlugin};

#[async_trait]
pub trait ClientModulePlugin: Debug {
    type Decoder: PluginDecode;
    type Module: ServerModulePlugin;

    const MODULE_KEY: ModuleKey;

    /// Returns the amount represented by the input and the fee its processing requires
    fn input_amount(
        &self,
        input: &<Self::Module as ServerModulePlugin>::Input,
    ) -> TransactionItemAmount;

    /// Returns the amount represented by the output and the fee its processing requires
    fn output_amount(
        &self,
        output: &<Self::Module as ServerModulePlugin>::Output,
    ) -> TransactionItemAmount;
}

pub trait IClientModule: Debug {
    fn module_key(&self) -> ModuleKey;

    fn as_any(&self) -> &(dyn Any + 'static);

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError>;
}

dyn_newtype_define!(
    #[derive(Clone)]
    pub ClientModule(Arc<IClientModule>)
);

impl<T> IClientModule for T
where
    T: ClientModulePlugin + 'static,
{
    fn module_key(&self) -> ModuleKey {
        <T as ClientModulePlugin>::MODULE_KEY
    }

    fn as_any(&self) -> &(dyn Any + 'static) {
        self
    }

    fn decode_input(&self, r: &mut dyn Read) -> Result<Input, DecodeError> {
        <<T as ClientModulePlugin>::Decoder as PluginDecode>::decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn Read) -> Result<Output, DecodeError> {
        <<T as ClientModulePlugin>::Decoder as PluginDecode>::decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn Read) -> Result<OutputOutcome, DecodeError> {
        <<T as ClientModulePlugin>::Decoder as PluginDecode>::decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn Read) -> Result<ConsensusItem, DecodeError> {
        <<T as ClientModulePlugin>::Decoder as PluginDecode>::decode_consensus_item(r)
    }
}

impl ModuleDecode for ClientModule {
    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        (**self).decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        (**self).decode_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        (**self).decode_output_outcome(r)
    }

    fn decode_consensus_item(&self, r: &mut dyn io::Read) -> Result<ConsensusItem, DecodeError> {
        (**self).decode_consensus_item(r)
    }
}

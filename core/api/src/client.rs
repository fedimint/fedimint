use std::sync::Arc;

use fedimint_api::dyn_newtype_define;

use super::*;

pub struct FedimintClientCore;

impl FedimintClientCore {
    // Exact args to be determeined
    pub fn call_federation(&self, _path: &str, _body: &[u8]) -> Vec<u8> {
        todo!()
    }
}

/// Client side module interface
pub trait IClientModule {
    fn module_key(&self) -> ModuleKey;

    fn decode_spendable_output(&self, r: &mut dyn io::Read)
        -> Result<SpendableOutput, DecodeError>;

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError>;

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError>;

    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError>;

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError>;

    /// `core` passed by value, so the module can store it
    fn init(&self, core: FedimintClientCore);

    fn poll_pending_output(
        &self,
        outputs: Vec<PendingOutput>,
    ) -> Result<PollPendingOutputs<SpendableOutput, PendingOutput>, FinalizationError>;
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub ClientModule(Arc<IClientModule>)
}

/// Result of [`ClientModulePlugin::poll_pending_outputs`]
pub struct PollPendingOutputs<S, P> {
    done: Vec<S>,
    pending: Vec<P>,
}

pub trait ClientModulePlugin: Sized {
    type Common: ModuleCommon;
    type Input: PluginInput;
    type Output: PluginOutput;
    type PendingOutput: PluginPendingOutput;
    type SpendableOutput: PluginSpendableOutput;
    type OutputOutcome: PluginOutputOutcome;

    fn init(&self, core: FedimintClientCore);
    fn poll_pending_outputs(
        &self,
        outputs: Vec<Self::PendingOutput>,
    ) -> Result<PollPendingOutputs<Self::SpendableOutput, Self::PendingOutput>, FinalizationError>;
}

impl<T> IClientModule for T
where
    T: ClientModulePlugin,
{
    fn module_key(&self) -> ModuleKey {
        <Self as ClientModulePlugin>::Common::module_key()
    }

    fn decode_spendable_output(
        &self,
        r: &mut dyn io::Read,
    ) -> Result<SpendableOutput, DecodeError> {
        <Self as ClientModulePlugin>::Common::decode_spendable_output(r)
    }

    fn decode_input(&self, r: &mut dyn io::Read) -> Result<Input, DecodeError> {
        <Self as ClientModulePlugin>::Common::decode_input(r)
    }

    fn decode_output(&self, r: &mut dyn io::Read) -> Result<Output, DecodeError> {
        <Self as ClientModulePlugin>::Common::decode_output(r)
    }

    fn decode_pending_output(&self, r: &mut dyn io::Read) -> Result<PendingOutput, DecodeError> {
        <Self as ClientModulePlugin>::Common::decode_pending_output(r)
    }

    fn decode_output_outcome(&self, r: &mut dyn io::Read) -> Result<OutputOutcome, DecodeError> {
        <Self as ClientModulePlugin>::Common::decode_output_outcome(r)
    }

    fn init(&self, core: FedimintClientCore) {
        <Self as ClientModulePlugin>::init(self, core)
    }

    fn poll_pending_output(
        &self,
        outputs: Vec<PendingOutput>,
    ) -> Result<PollPendingOutputs<SpendableOutput, PendingOutput>, FinalizationError> {
        let outputs: Vec<<Self as ClientModulePlugin>::PendingOutput> = outputs
            .into_iter()
            .map(|o| {
                Clone::clone(
                    o.as_any()
                        .downcast_ref::<<Self as ClientModulePlugin>::PendingOutput>()
                        .expect("incorrect type output type passed to module plugin"),
                )
            })
            .collect();

        let PollPendingOutputs { done, pending } =
            <Self as ClientModulePlugin>::poll_pending_outputs(self, outputs)?;

        Ok(PollPendingOutputs {
            done: done.into_iter().map(Into::into).collect(),
            pending: pending.into_iter().map(Into::into).collect(),
        })
    }
}

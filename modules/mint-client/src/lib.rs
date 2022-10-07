use fedimint_api::module::{
    ClientModulePlugin, FedimintClientCore, Output, PendingOutput, PollPendingOutputs,
};
use fedimint_api::Amount;
use fedimint_mint_common::{
    MintInput, MintModuleCommon, MintOutput, MintOutputOutcome, MintPendingOutput,
    MintSpendableOutput,
};

#[derive(Clone)]
pub struct MintModuleClientConfig {
    #[allow(unused)]
    pub some_number: u32,
}

#[derive(Clone)]
pub struct MintClientModule {
    #[allow(unused)]
    config: MintModuleClientConfig,
}

impl MintClientModule {
    #[allow(clippy::new_ret_no_self)]
    pub fn from_config(config: MintModuleClientConfig) -> MintClientModule {
        Self { config }
    }

    /// Generate a transaction [`Output`] and a corresponding [`PendingOutput`]
    ///
    /// This method is not a trait itself, because every module will require its
    /// own module-specific inputs to create an output.
    pub fn generate_output(
        &self,
        _amount: Amount,
        _deterministic_rand: [u8; 32],
    ) -> (Output, PendingOutput) {
        (
            Output::from(MintOutput),
            PendingOutput::from(MintPendingOutput),
        )
    }

    pub fn generate_outputs<F>(
        &self,
        _amount: Amount,
        _get_deterministic_rand: F,
    ) -> Vec<(Output, PendingOutput)>
    where
        F: Fn() -> [u8; 32],
    {
        todo!()
    }
}

impl ClientModulePlugin for MintClientModule {
    type Decoder = MintModuleCommon;
    type Input = MintInput;
    type Output = MintOutput;
    type PendingOutput = MintPendingOutput;
    type SpendableOutput = MintSpendableOutput;
    type OutputOutcome = MintOutputOutcome;

    fn init(&self, _core: FedimintClientCore) {
        todo!()
    }

    fn poll_pending_outputs(
        &self,
        _outputs: Vec<MintPendingOutput>,
    ) -> Result<
        PollPendingOutputs<MintSpendableOutput, MintPendingOutput>,
        fedimint_api::module::FinalizationError,
    > {
        todo!()
    }
}

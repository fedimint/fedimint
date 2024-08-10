use std::sync::Arc;

use bitcoin::key::KeyPair;
use bitcoin::secp256k1;
use fedimint_core::core::{DynInput, DynOutput, IntoDynInstance, ModuleInstanceId};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::Amount;
use itertools::multiunzip;
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::Secp256k1;

use crate::module::StateGenerator;
use crate::sm::DynState;

#[derive(Clone)]
pub struct ClientInput<I = DynInput, S = DynState> {
    pub input: I,
    pub keys: Vec<KeyPair>,
    pub amount: Amount,
    pub state_machines: StateGenerator<S>,
}

impl<I, S> IntoDynInstance for ClientInput<I, S>
where
    I: IntoDynInstance<DynType = DynInput> + 'static,
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientInput;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInput {
        ClientInput {
            input: self.input.into_dyn(module_instance_id),
            keys: self.keys,
            amount: self.amount,
            state_machines: state_gen_to_dyn(self.state_machines, module_instance_id),
        }
    }
}

#[derive(Clone)]
pub struct ClientOutput<O = DynOutput, S = DynState> {
    pub output: O,
    pub amount: Amount,
    pub state_machines: StateGenerator<S>,
}

impl<O, S> IntoDynInstance for ClientOutput<O, S>
where
    O: IntoDynInstance<DynType = DynOutput> + 'static,
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientOutput;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientOutput {
        ClientOutput {
            output: self.output.into_dyn(module_instance_id),
            amount: self.amount,
            state_machines: state_gen_to_dyn(self.state_machines, module_instance_id),
        }
    }
}

#[derive(Default, Clone)]
pub struct TransactionBuilder {
    pub(crate) change_strategy: ChangeStrategy,
    pub(crate) inputs: Vec<ClientInput>,
    pub(crate) outputs: Vec<ClientOutput>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_input(mut self, input: ClientInput) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn with_output(mut self, output: ClientOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn with_inputs(mut self, inputs: Vec<ClientInput>) -> Self {
        for input in inputs {
            self.inputs.push(input);
        }

        self
    }

    pub fn with_outputs(mut self, outputs: Vec<ClientOutput>) -> Self {
        for output in outputs {
            self.outputs.push(output);
        }

        self
    }

    /// Set the [`ChangeStrategy`] for the transaction to control how many
    /// change outputs are generated. Defaults to
    /// [`ChangeStrategy::OptimizeWallet`].
    pub fn with_change_strategy(mut self, change_strategy: ChangeStrategy) -> Self {
        self.change_strategy = change_strategy;
        self
    }

    pub fn build<C, R: RngCore + CryptoRng>(
        self,
        secp_ctx: &Secp256k1<C>,
        mut rng: R,
    ) -> (Transaction, Vec<DynState>)
    where
        C: secp256k1::Signing + secp256k1::Verification,
    {
        let (inputs, input_keys, input_states): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            self.inputs
                .into_iter()
                .map(|input| (input.input, input.keys, input.state_machines)),
        );
        let (outputs, output_states): (Vec<_>, Vec<_>) = self
            .outputs
            .into_iter()
            .map(|output| (output.output, output.state_machines))
            .unzip();

        let nonce: [u8; 8] = rng.gen();

        let txid = Transaction::tx_hash_from_parts(&inputs, &outputs, nonce);
        let msg = secp256k1::Message::from_slice(&txid[..]).expect("txid has right length");

        let signatures = input_keys
            .into_iter()
            .flatten()
            .map(|keypair| secp_ctx.sign_schnorr(&msg, &keypair))
            .collect();

        let transaction = Transaction {
            inputs,
            outputs,
            nonce,
            signatures: TransactionSignature::NaiveMultisig(signatures),
        };

        let states = input_states
            .into_iter()
            .enumerate()
            .chain(output_states.into_iter().enumerate())
            .flat_map(|(idx, state_gen)| state_gen(txid, idx as u64))
            .collect::<Vec<_>>();

        (transaction, states)
    }
}

fn state_gen_to_dyn<S>(
    state_gen: StateGenerator<S>,
    module_instance: ModuleInstanceId,
) -> StateGenerator<DynState>
where
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    Arc::new(move |txid, index| {
        let states = state_gen(txid, index);
        states
            .into_iter()
            .map(|state| state.into_dyn(module_instance))
            .collect()
    })
}

/// Indicates to the primary module how it is supposed to generate change
/// outputs for the transaction. Not all primary modules will know how to handle
/// all strategies, they should just ignore them in that case.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ChangeStrategy {
    /// The primary module should minimize the number of change outputs.
    ///
    /// This is particularly useful for e-cash refunds where we know that the
    /// wallet state before the OOB spend was good and the parallel refund of
    /// many notes would lead to issuing too many small notes.
    Minimize,
    /// The primary module should optimize the wallet by creating change outputs
    /// as needed to approximate the desired wallet structure.
    ///
    /// In case of the mint module that means creating small denomination notes
    /// first in case we are missing these in the wallet and only using the
    /// remaining funds for creating larger denominations.
    #[default]
    OptimizeWallet,
}

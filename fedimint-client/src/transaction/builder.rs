use std::sync::Arc;

use fedimint_core::core::{DynInput, DynOutput, IntoDynInstance, ModuleInstanceId};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::Amount;
use itertools::multiunzip;
use rand::{CryptoRng, Rng, RngCore};
use secp256k1_zkp::Secp256k1;

use crate::module::StateGenerator;
use crate::sm::DynState;
use crate::transaction::DynSchnorrSigner;

#[derive(Clone)]
pub struct ClientInput<K = DynSchnorrSigner, I = DynInput, S = DynState> {
    pub input: I,
    pub keys: Vec<K>,
    pub amount: Amount,
    pub state_machines: StateGenerator<S>,
}

impl<K, I, S> IntoDynInstance for ClientInput<K, I, S>
where
    K: IntoDynInstance<DynType = DynSchnorrSigner> + 'static,
    I: IntoDynInstance<DynType = DynInput> + 'static,
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientInput;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInput {
        ClientInput {
            input: self.input.into_dyn(module_instance_id),
            keys: self
                .keys
                .into_iter()
                .map(|k| k.into_dyn(module_instance_id))
                .collect(),
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

    pub fn build<C, R: RngCore + CryptoRng>(
        self,
        _secp_ctx: &Secp256k1<C>,
        mut rng: R,
    ) -> (Transaction, Vec<DynState>)
    where
        C: secp256k1_zkp::Signing + secp256k1_zkp::Verification,
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
        let msg = secp256k1_zkp::Message::from_slice(&txid[..]).expect("txid has right length");

        let secp = Secp256k1::new(); // todo use provided one
        let signatures = input_keys
            .into_iter()
            .flatten()
            .map(|keypair| keypair.0.sign_schnorr(&secp, &msg))
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

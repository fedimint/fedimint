use fedimint_core::core::{DynInput, DynOutput, KeyPair};
use fedimint_core::transaction::Transaction;
use fedimint_core::Amount;
use itertools::multiunzip;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::Secp256k1;

use crate::module::StateGenerator;
use crate::sm::DynState;
use crate::DynGlobalClientContext;

pub struct ClientInput {
    pub input: DynInput,
    pub keys: Vec<KeyPair>,
    pub state_machines: StateGenerator<DynState<DynGlobalClientContext>>,
}

pub struct ClientOutput {
    pub output: DynOutput,
    pub state_machines: StateGenerator<DynState<DynGlobalClientContext>>,
}

#[derive(Default)]
pub struct TransactionBuilder {
    pub(crate) inputs: Vec<ClientInput>,
    pub(crate) outputs: Vec<ClientOutput>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_input(&mut self, input: ClientInput) {
        self.inputs.push(input)
    }

    pub fn with_output(&mut self, output: ClientOutput) {
        self.outputs.push(output)
    }

    pub fn build<C, R: RngCore + CryptoRng>(
        self,
        secp_ctx: &Secp256k1<C>,
        mut rng: R,
    ) -> (Transaction, Vec<DynState<DynGlobalClientContext>>)
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

        let txid = Transaction::tx_hash_from_parts(&inputs, &outputs);

        let signature = if !input_keys.is_empty() {
            let keys = input_keys.into_iter().flatten().collect::<Vec<_>>();

            let signature =
                fedimint_core::transaction::agg_sign(&keys, txid.as_hash(), secp_ctx, &mut rng);
            Some(signature)
        } else {
            None
        };

        let transaction = Transaction {
            inputs,
            outputs,
            signature,
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

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TransactionBuilderBalance {
    Underfunded(Amount),
    Balanced,
    Overfunded(Amount),
}

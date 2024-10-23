use std::sync::Arc;

use bitcoin::key::Keypair;
use bitcoin::secp256k1;
use fedimint_core::bitcoin_migration::bitcoin32_to_bitcoin30_schnorr_signature;
use fedimint_core::core::{DynInput, DynOutput, IInput, IntoDynInstance, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::Amount;
use itertools::multiunzip;
use rand::{CryptoRng, Rng, RngCore};
use secp256k1::Secp256k1;

use crate::module::StateGenerator;
use crate::sm::{self, DynState};
use crate::{
    states_to_instanceless_dyn, InstancelessDynClientInput, InstancelessDynClientInputBundle,
    InstancelessDynClientInputSM,
};

#[derive(Clone)]
pub struct ClientInput<I = DynInput> {
    pub input: I,
    pub keys: Vec<Keypair>,
    pub amount: Amount,
}

#[derive(Clone)]
pub struct ClientInputSM<S = DynState> {
    pub state_machines: StateGenerator<S>,
}

/// A fake [`sm::Context`] for [`NeverClientStateMachine`]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum NeverClientContext {}

impl sm::Context for NeverClientContext {
    const KIND: Option<fedimint_core::core::ModuleKind> = None;
}

/// A fake [`sm::State`] that can actually never happen.
///
/// Useful as a default for type inference in cases where there are no
/// state machines involved in [`ClientInputBundle`].
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum NeverClientStateMachine {}

impl IntoDynInstance for NeverClientStateMachine {
    type DynType = DynState;

    fn into_dyn(self, _instance_id: ModuleInstanceId) -> Self::DynType {
        unreachable!()
    }
}
impl sm::State for NeverClientStateMachine {
    type ModuleContext = NeverClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &crate::DynGlobalClientContext,
    ) -> Vec<sm::StateTransition<Self>> {
        unreachable!()
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        unreachable!()
    }
}

/// A group of inputs and state machines responsible for driving their state
///
/// These must be kept together as a whole when including in a transaction.
#[derive(Clone)]
pub struct ClientInputBundle<I = DynInput, S = DynState> {
    pub(crate) inputs: Vec<ClientInput<I>>,
    pub(crate) sms: Vec<ClientInputSM<S>>,
}

impl<I> ClientInputBundle<I, NeverClientStateMachine> {
    /// A version of [`Self::new`] for times where input does not require any
    /// state machines
    ///
    /// This avoids type inference issues of `S`, and saves some typing.
    pub fn new_no_sm(inputs: Vec<ClientInput<I>>) -> Self {
        Self {
            inputs,
            sms: vec![],
        }
    }
}

impl<I, S> ClientInputBundle<I, S>
where
    I: IInput + MaybeSend + MaybeSync + 'static,
    S: sm::IState + MaybeSend + MaybeSync + 'static,
{
    pub fn new(inputs: Vec<ClientInput<I>>, sms: Vec<ClientInputSM<S>>) -> Self {
        Self { inputs, sms }
    }

    pub fn inputs(&self) -> &[ClientInput<I>] {
        &self.inputs
    }

    pub fn sms(&self) -> &[ClientInputSM<S>] {
        &self.sms
    }

    pub fn with(mut self, other: Self) -> Self {
        self.inputs.extend(other.inputs);
        self.sms.extend(other.sms);
        self
    }

    pub fn into_instanceless(self) -> InstancelessDynClientInputBundle {
        InstancelessDynClientInputBundle {
            inputs: self
                .inputs
                .into_iter()
                .map(|input| InstancelessDynClientInput {
                    input: Box::new(input.input),
                    keys: input.keys,
                    amount: input.amount,
                })
                .collect(),
            sms: self
                .sms
                .into_iter()
                .map(|input_sm| InstancelessDynClientInputSM {
                    state_machines: states_to_instanceless_dyn(input_sm.state_machines),
                })
                .collect(),
        }
    }
}
impl<I> IntoDynInstance for ClientInput<I>
where
    I: IntoDynInstance<DynType = DynInput> + 'static,
{
    type DynType = ClientInput;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInput {
        ClientInput {
            input: self.input.into_dyn(module_instance_id),
            keys: self.keys,
            amount: self.amount,
        }
    }
}

impl<S> IntoDynInstance for ClientInputSM<S>
where
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientInputSM;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInputSM {
        ClientInputSM {
            state_machines: state_gen_to_dyn(self.state_machines, module_instance_id),
        }
    }
}

impl<I, S> IntoDynInstance for ClientInputBundle<I, S>
where
    I: IntoDynInstance<DynType = DynInput> + 'static,
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientInputBundle;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInputBundle {
        ClientInputBundle {
            inputs: self
                .inputs
                .into_iter()
                .map(|input| input.into_dyn(module_instance_id))
                .collect::<Vec<ClientInput>>(),

            sms: self
                .sms
                .into_iter()
                .map(|input_sm| input_sm.into_dyn(module_instance_id))
                .collect::<Vec<ClientInputSM>>(),
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
    inputs: Vec<ClientInput>,
    input_sms: Vec<ClientInputSM>,
    outputs: Vec<ClientOutput>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inputs(&self) -> &[ClientInput] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[ClientOutput] {
        &self.outputs
    }

    pub fn with_input(mut self, input: ClientInput) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn with_input_sm(mut self, input: ClientInputSM) -> Self {
        self.input_sms.push(input);
        self
    }

    pub fn with_inputs(mut self, inputs: ClientInputBundle) -> Self {
        self.inputs.extend(inputs.inputs);
        self.input_sms.extend(inputs.sms);
        self
    }

    pub fn with_output(mut self, output: ClientOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn with_input_sms(mut self, input_sms: Vec<ClientInputSM>) -> Self {
        for input_sm in input_sms {
            self.input_sms.push(input_sm);
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
        secp_ctx: &Secp256k1<C>,
        mut rng: R,
    ) -> (Transaction, Vec<DynState>)
    where
        C: secp256k1::Signing + secp256k1::Verification,
    {
        let (inputs, input_keys): (Vec<_>, Vec<_>) = multiunzip(
            self.inputs
                .into_iter()
                .map(|input| (input.input, input.keys)),
        );
        let input_sms: Vec<_> = self
            .input_sms
            .into_iter()
            .map(|input_sm| (input_sm.state_machines))
            .collect();

        let (outputs, output_states): (Vec<_>, Vec<_>) = self
            .outputs
            .into_iter()
            .map(|output| (output.output, output.state_machines))
            .unzip();

        let nonce: [u8; 8] = rng.gen();

        let txid = Transaction::tx_hash_from_parts(&inputs, &outputs, nonce);
        let msg = secp256k1::Message::from_digest_slice(&txid[..]).expect("txid has right length");

        let signatures = input_keys
            .into_iter()
            .flatten()
            .map(|keypair| {
                bitcoin32_to_bitcoin30_schnorr_signature(&secp_ctx.sign_schnorr(&msg, &keypair))
            })
            .collect();

        let transaction = Transaction {
            inputs,
            outputs,
            nonce,
            signatures: TransactionSignature::NaiveMultisig(signatures),
        };

        let states = input_sms
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

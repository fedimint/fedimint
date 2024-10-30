use std::sync::Arc;

use bitcoin::key::Keypair;
use bitcoin::secp256k1;
use fedimint_core::bitcoin_migration::bitcoin32_to_bitcoin30_schnorr_signature;
use fedimint_core::core::{
    DynInput, DynOutput, IInput, IOutput, IntoDynInstance, ModuleInstanceId,
};
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
    InstancelessDynClientInputSM, InstancelessDynClientOutput, InstancelessDynClientOutputBundle,
    InstancelessDynClientOutputSM,
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
pub struct ClientOutputBundle<O = DynOutput, S = DynState> {
    pub(crate) outputs: Vec<ClientOutput<O>>,
    pub(crate) sms: Vec<ClientOutputSM<S>>,
}

#[derive(Clone)]
pub struct ClientOutput<O = DynOutput> {
    pub output: O,
    pub amount: Amount,
}

#[derive(Clone)]
pub struct ClientOutputSM<S = DynState> {
    pub state_machines: StateGenerator<S>,
}

impl<O> ClientOutputBundle<O, NeverClientStateMachine> {
    /// A version of [`Self::new`] for times where output does not require any
    /// state machines
    ///
    /// This avoids type inference issues of `S`, and saves some typing.
    pub fn new_no_sm(outputs: Vec<ClientOutput<O>>) -> Self {
        Self {
            outputs,
            sms: vec![],
        }
    }
}

impl<O, S> ClientOutputBundle<O, S>
where
    O: IOutput + MaybeSend + MaybeSync + 'static,
    S: sm::IState + MaybeSend + MaybeSync + 'static,
{
    pub fn new(outputs: Vec<ClientOutput<O>>, sms: Vec<ClientOutputSM<S>>) -> Self {
        Self { outputs, sms }
    }

    pub fn outputs(&self) -> &[ClientOutput<O>] {
        &self.outputs
    }

    pub fn sms(&self) -> &[ClientOutputSM<S>] {
        &self.sms
    }

    pub fn with(mut self, other: Self) -> Self {
        self.outputs.extend(other.outputs);
        self.sms.extend(other.sms);
        self
    }

    pub fn into_instanceless(self) -> InstancelessDynClientOutputBundle {
        InstancelessDynClientOutputBundle {
            outputs: self
                .outputs
                .into_iter()
                .map(|output| InstancelessDynClientOutput {
                    output: Box::new(output.output),
                    amount: output.amount,
                })
                .collect(),
            sms: self
                .sms
                .into_iter()
                .map(|output_sm| InstancelessDynClientOutputSM {
                    state_machines: states_to_instanceless_dyn(output_sm.state_machines),
                })
                .collect(),
        }
    }
}

impl<I, S> IntoDynInstance for ClientOutputBundle<I, S>
where
    I: IntoDynInstance<DynType = DynOutput> + 'static,
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientOutputBundle;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientOutputBundle {
        ClientOutputBundle {
            outputs: self
                .outputs
                .into_iter()
                .map(|output| output.into_dyn(module_instance_id))
                .collect::<Vec<ClientOutput>>(),

            sms: self
                .sms
                .into_iter()
                .map(|output_sm| output_sm.into_dyn(module_instance_id))
                .collect::<Vec<ClientOutputSM>>(),
        }
    }
}

impl<I> IntoDynInstance for ClientOutput<I>
where
    I: IntoDynInstance<DynType = DynOutput> + 'static,
{
    type DynType = ClientOutput;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientOutput {
        ClientOutput {
            output: self.output.into_dyn(module_instance_id),
            amount: self.amount,
        }
    }
}

impl<S> IntoDynInstance for ClientOutputSM<S>
where
    S: IntoDynInstance<DynType = DynState> + 'static,
{
    type DynType = ClientOutputSM;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientOutputSM {
        ClientOutputSM {
            state_machines: state_gen_to_dyn(self.state_machines, module_instance_id),
        }
    }
}

#[derive(Default, Clone)]
pub struct TransactionBuilder {
    inputs: Vec<ClientInput>,
    input_sms: Vec<ClientInputSM>,
    outputs: Vec<ClientOutput>,
    output_sms: Vec<ClientOutputSM>,
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

    pub fn with_output(mut self, output: ClientOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn with_output_sm(mut self, output: ClientOutputSM) -> Self {
        self.output_sms.push(output);
        self
    }

    pub fn with_inputs(mut self, inputs: ClientInputBundle) -> Self {
        self.inputs.extend(inputs.inputs);
        self.input_sms.extend(inputs.sms);
        self
    }

    pub fn with_outputs(mut self, outputs: ClientOutputBundle) -> Self {
        self.outputs.extend(outputs.outputs);
        self.output_sms.extend(outputs.sms);
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

        let outputs: Vec<_> = self
            .outputs
            .into_iter()
            .map(|output| output.output)
            .collect();

        let output_sms: Vec<_> = self
            .output_sms
            .into_iter()
            .map(|output_sm| (output_sm.state_machines))
            .collect();

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
            .chain(output_sms.into_iter().enumerate())
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

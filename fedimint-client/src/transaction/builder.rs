use std::fmt;
use std::ops::RangeInclusive;
use std::sync::Arc;

use bitcoin::key::Keypair;
use bitcoin::secp256k1;
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

use crate::module::{IdxRange, StateGenerator};
use crate::sm::{self, DynState};
use crate::{
    states_add_instance, states_to_instanceless_dyn, InstancelessDynClientInput,
    InstancelessDynClientInputBundle, InstancelessDynClientInputSM, InstancelessDynClientOutput,
    InstancelessDynClientOutputBundle, InstancelessDynClientOutputSM,
};

#[derive(Clone, Debug)]
pub struct ClientInput<I = DynInput> {
    pub input: I,
    pub keys: Vec<Keypair>,
    pub amount: Amount,
}

#[derive(Clone)]
pub struct ClientInputSM<S = DynState> {
    pub state_machines: StateGenerator<S>,
}

impl<S> fmt::Debug for ClientInputSM<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientInputSM")
    }
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
#[derive(Clone, Debug)]
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

impl IntoDynInstance for InstancelessDynClientInputBundle {
    type DynType = ClientInputBundle;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientInputBundle {
        ClientInputBundle {
            inputs: self
                .inputs
                .into_iter()
                .map(|input| ClientInput {
                    input: DynInput::from_parts(module_instance_id, input.input),
                    keys: input.keys,
                    amount: input.amount,
                })
                .collect::<Vec<ClientInput>>(),

            sms: self
                .sms
                .into_iter()
                .map(|input_sm| ClientInputSM {
                    state_machines: states_add_instance(
                        module_instance_id,
                        input_sm.state_machines,
                    ),
                })
                .collect::<Vec<ClientInputSM>>(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientOutputBundle<O = DynOutput, S = DynState> {
    pub(crate) outputs: Vec<ClientOutput<O>>,
    pub(crate) sms: Vec<ClientOutputSM<S>>,
}

#[derive(Clone, Debug)]
pub struct ClientOutput<O = DynOutput> {
    pub output: O,
    pub amount: Amount,
}

#[derive(Clone)]
pub struct ClientOutputSM<S = DynState> {
    pub state_machines: StateGenerator<S>,
}

impl<S> fmt::Debug for ClientOutputSM<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientOutputSM")
    }
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

impl IntoDynInstance for InstancelessDynClientOutputBundle {
    type DynType = ClientOutputBundle;

    fn into_dyn(self, module_instance_id: ModuleInstanceId) -> ClientOutputBundle {
        ClientOutputBundle {
            outputs: self
                .outputs
                .into_iter()
                .map(|output| ClientOutput {
                    output: DynOutput::from_parts(module_instance_id, output.output),
                    amount: output.amount,
                })
                .collect::<Vec<ClientOutput>>(),

            sms: self
                .sms
                .into_iter()
                .map(|output_sm| ClientOutputSM {
                    state_machines: states_add_instance(
                        module_instance_id,
                        output_sm.state_machines,
                    ),
                })
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

#[derive(Default, Clone, Debug)]
pub struct TransactionBuilder {
    inputs: Vec<ClientInputBundle>,
    outputs: Vec<ClientOutputBundle>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_inputs(mut self, inputs: ClientInputBundle) -> Self {
        self.inputs.push(inputs);
        self
    }

    pub fn with_outputs(mut self, outputs: ClientOutputBundle) -> Self {
        self.outputs.push(outputs);
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
        // `input_idx_to_bundle_idx[input_idx]` stores the index of a bundle the input
        // at `input_idx` comes from, so we can call state machines of the
        // corresponding bundle for every input bundle. It is always
        // monotonically increasing, e.g. `[0, 0, 1, 2, 2, 2, 4]`
        let (input_idx_to_bundle_idx, inputs, input_keys): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
            self.inputs
                .iter()
                .enumerate()
                .flat_map(|(bundle_idx, bundle)| {
                    bundle
                        .inputs
                        .iter()
                        .map(move |input| (bundle_idx, input.input.clone(), input.keys.clone()))
                }),
        );
        // `output_idx_to_bundle` works exactly like `input_idx_to_bundle_idx` above,
        // but for outputs.
        let (output_idx_to_bundle_idx, outputs): (Vec<_>, Vec<_>) = multiunzip(
            self.outputs
                .iter()
                .enumerate()
                .flat_map(|(bundle_idx, bundle)| {
                    bundle
                        .outputs
                        .iter()
                        .map(move |output| (bundle_idx, output.output.clone()))
                }),
        );
        let nonce: [u8; 8] = rng.gen();

        let txid = Transaction::tx_hash_from_parts(&inputs, &outputs, nonce);
        let msg = secp256k1::Message::from_digest_slice(&txid[..]).expect("txid has right length");

        let signatures = input_keys
            .iter()
            .flatten()
            .map(|keypair| secp_ctx.sign_schnorr(&msg, keypair))
            .collect();

        let transaction = Transaction {
            inputs,
            outputs,
            nonce,
            signatures: TransactionSignature::NaiveMultisig(signatures),
        };

        let input_states = self
            .inputs
            .into_iter()
            .enumerate()
            .flat_map(|(bundle_idx, bundle)| {
                let input_idxs = find_range_of_matching_items(&input_idx_to_bundle_idx, bundle_idx);
                bundle.sms.into_iter().flat_map(move |sm| {
                    if let Some(input_idxs) = input_idxs.as_ref() {
                        (sm.state_machines)(txid, IdxRange::from(input_idxs.clone()))
                    } else {
                        vec![]
                    }
                })
            });

        let output_states =
            self.outputs
                .into_iter()
                .enumerate()
                .flat_map(|(bundle_idx, bundle)| {
                    let output_idxs =
                        find_range_of_matching_items(&output_idx_to_bundle_idx, bundle_idx);
                    bundle.sms.into_iter().flat_map(move |sm| {
                        if let Some(output_idxs) = output_idxs.as_ref() {
                            (sm.state_machines)(txid, IdxRange::from(output_idxs.clone()))
                        } else {
                            vec![]
                        }
                    })
                });
        (transaction, input_states.chain(output_states).collect())
    }

    pub(crate) fn inputs(&self) -> impl Iterator<Item = &ClientInput> {
        self.inputs.iter().flat_map(|i| i.inputs.iter())
    }

    pub(crate) fn outputs(&self) -> impl Iterator<Item = &ClientOutput> {
        self.outputs.iter().flat_map(|i| i.outputs.iter())
    }
}

/// Find the range of indexes in an monotonically increasing `arr`, that is
/// equal to `item`
fn find_range_of_matching_items(arr: &[usize], item: usize) -> Option<RangeInclusive<u64>> {
    // `arr` must be monotonically increasing
    debug_assert!(arr.windows(2).all(|w| w[0] <= w[1]));

    arr.iter()
        .enumerate()
        .filter_map(|(arr_idx, arr_item)| (*arr_item == item).then_some(arr_idx as u64))
        .fold(None, |cur: Option<(u64, u64)>, idx| {
            Some(cur.map_or((idx, idx), |cur| (cur.0.min(idx), cur.1.max(idx))))
        })
        .map(|(start, end)| start..=end)
}

#[test]
fn find_range_of_matching_items_sanity() {
    assert_eq!(find_range_of_matching_items(&[0, 0], 0), Some(0..=1));
    assert_eq!(find_range_of_matching_items(&[0, 0, 1], 0), Some(0..=1));
    assert_eq!(find_range_of_matching_items(&[0, 0, 1], 1), Some(2..=2));
    assert_eq!(find_range_of_matching_items(&[0, 0, 1], 2), None);
    assert_eq!(find_range_of_matching_items(&[], 0), None);
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

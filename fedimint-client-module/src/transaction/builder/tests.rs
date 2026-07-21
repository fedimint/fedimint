use core::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use bitcoin::key::Secp256k1;
use fedimint_core::Amount;
use fedimint_core::core::{Input, IntoDynInstance, ModuleKind, Output};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;

use super::{
    ClientInputBundle, ClientOutput, ClientOutputBundle, ClientOutputSM, FeeQuote,
    TransactionBuilder, max_affordable_send_amount,
};
use crate::module::OutPointRange;
use crate::transaction::{ClientInput, ClientInputSM};

#[derive(Encodable, Decodable, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoopInput;

impl fmt::Display for NoopInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoopInput")
    }
}

impl Input for NoopInput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl IntoDynInstance for NoopInput {
    type DynType = fedimint_core::core::DynInput;

    fn into_dyn(self, instance_id: fedimint_core::core::ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynInput::from_typed(instance_id, self)
    }
}

#[derive(Encodable, Decodable, Clone, Debug, Hash, PartialEq, Eq)]
pub struct NoopOutput;

impl fmt::Display for NoopOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoopOutput")
    }
}

impl Output for NoopOutput {
    const KIND: ModuleKind = ModuleKind::from_static_str("test");
}

impl IntoDynInstance for NoopOutput {
    type DynType = fedimint_core::core::DynOutput;

    fn into_dyn(self, instance_id: fedimint_core::core::ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynOutput::from_typed(instance_id, self)
    }
}

#[test]
/// Exercise empty bundles
///
/// Actually exercise empty bundles (since it's rare in real code)
/// and ensure that their SM-gens are *not* called, while the SM-gens
/// of non-empty bundles work as expected.
fn tx_builder_empty_bundles() {
    // We'll collect ranges sms were called into this thing to compare at the end
    let sm_called = Arc::new(Mutex::new(String::new()));

    let no_call_input_sm = ClientInputSM {
        state_machines: Arc::new(move |_out_point_range: OutPointRange| {
            panic!("Don't call me maybe");
        }),
    };

    let no_call_output_sm = ClientOutputSM {
        state_machines: Arc::new(move |_out_point_range: OutPointRange| {
            panic!("Don't call me maybe");
        }),
    };
    let yes_call_input_sm = ClientInputSM {
        state_machines: Arc::new({
            let sm_called = sm_called.clone();
            move |out_point_range: OutPointRange| {
                sm_called
                    .lock()
                    .unwrap()
                    .write_fmt(format_args!("i-{:?},", out_point_range.start_idx()))
                    .expect("Can't fail");
                vec![]
            }
        }),
    };

    let yes_call_output_sm = ClientOutputSM {
        state_machines: Arc::new({
            let sm_called = sm_called.clone();
            move |out_point_range: OutPointRange| {
                sm_called
                    .clone()
                    .lock()
                    .unwrap()
                    .write_fmt(format_args!("o-{:?},", out_point_range.start_idx()))
                    .expect("Can't fail");
                vec![]
            }
        }),
    };

    // This is ugly due to repetition, but the more manual, the better, and in real
    // code some of these conversions are hidden in the generics. Oh well.
    TransactionBuilder::new()
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(vec![], vec![no_call_input_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(
                vec![ClientInput {
                    input: NoopInput,
                    keys: vec![],
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_input_sm.clone()],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(vec![], vec![no_call_input_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_inputs(
            ClientInputBundle::<NoopInput>::new(
                vec![ClientInput {
                    input: NoopInput,
                    keys: vec![],
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_input_sm],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(vec![], vec![no_call_output_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(
                vec![ClientOutput {
                    output: NoopOutput,
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_output_sm.clone()],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(vec![], vec![no_call_output_sm.clone()])
                .into_instanceless()
                .into_dyn(0),
        )
        .with_outputs(
            ClientOutputBundle::<NoopOutput>::new(
                vec![ClientOutput {
                    output: NoopOutput,
                    amounts: Amounts::new_bitcoin_msats(1),
                }],
                vec![yes_call_output_sm],
            )
            .into_instanceless()
            .into_dyn(3),
        )
        .build(&Secp256k1::new(), rand::thread_rng());

    // This actually depends on how builder processes inputs and outputs,
    // but if it ever changes, just adjust the string.
    assert_eq!(*sm_called.lock().unwrap(), String::from("i-0,i-1,o-0,o-1,"));
}

/// A federation fee quote whose only cost is `fee` in the Bitcoin unit, so
/// `total().get_bitcoin() == fee`.
fn federation_fee(fee: Amount) -> FeeQuote {
    FeeQuote {
        input: Amounts::new_bitcoin(fee),
        output: Amounts::ZERO,
        dust: Amounts::ZERO,
    }
}

#[tokio::test]
async fn max_affordable_no_fees_spends_whole_balance() {
    let balance = Amount::from_msats(1_000_000);

    let result = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        |invoice| invoice, // no gateway fee
        |_contract| async { Ok(federation_fee(Amount::ZERO)) },
    )
    .await;

    assert_eq!(result, Some(balance));
}

#[tokio::test]
async fn max_affordable_leaves_room_for_gateway_fee() {
    // Gateway fee: 1000 msat base + 10% proportional.
    let gross_up = |invoice: Amount| Amount::from_msats(invoice.msats + 1000 + invoice.msats / 10);
    let balance = Amount::from_msats(1_000_000);

    let x = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        gross_up,
        |_contract| async { Ok(federation_fee(Amount::ZERO)) },
    )
    .await
    .expect("balance covers a payment")
    .msats;

    // `x` is payable but `x + 1` is not: exactly the maximum.
    assert!(gross_up(Amount::from_msats(x)).msats <= balance.msats);
    assert!(gross_up(Amount::from_msats(x + 1)).msats > balance.msats);
}

#[tokio::test]
async fn max_affordable_leaves_room_for_module_fee() {
    // Federation fee: 500 msat base + 5% of the contract amount.
    let module_fee = |contract: Amount| Amount::from_msats(500 + contract.msats / 20);
    let balance = Amount::from_msats(1_000_000);

    let x = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        |invoice| invoice, // no gateway fee, so contract == invoice
        move |contract| async move { Ok(federation_fee(module_fee(contract))) },
    )
    .await
    .expect("balance covers a payment")
    .msats;

    let cost = |v: u64| v + module_fee(Amount::from_msats(v)).msats;
    assert!(cost(x) <= balance.msats);
    assert!(cost(x + 1) > balance.msats);
}

#[tokio::test]
async fn max_affordable_handles_stepwise_fee() {
    // A fee that is NOT a linear function of the amount: it jumps once the
    // contract crosses a threshold, as selecting an extra funding note would.
    // A closed form assuming a linear fee would missolve this.
    let module_fee = |contract: Amount| {
        if contract.msats > 500_000 {
            Amount::from_msats(100_000)
        } else {
            Amount::ZERO
        }
    };
    let balance = Amount::from_msats(550_000);

    let result = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        |invoice| invoice,
        move |contract| async move { Ok(federation_fee(module_fee(contract))) },
    )
    .await;

    // Above 500_000 the fee jump pushes the total over the balance, so the
    // maximum spendable amount sits exactly at the step.
    assert_eq!(result, Some(Amount::from_msats(500_000)));
}

#[tokio::test]
async fn max_affordable_respects_max_bound() {
    let balance = Amount::from_msats(1_000_000);

    let result = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        Amount::from_msats(100), // cap well below the balance
        |invoice| invoice,
        |_contract| async { Ok(federation_fee(Amount::ZERO)) },
    )
    .await;

    assert_eq!(result, Some(Amount::from_msats(100)));
}

#[tokio::test]
async fn max_affordable_none_when_min_unaffordable() {
    // Balance can't even cover the gateway base fee on the smallest send.
    let balance = Amount::from_msats(10);

    let result = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        |invoice: Amount| Amount::from_msats(invoice.msats + 1000), // 1000 msat base fee
        |_contract| async { Ok(federation_fee(Amount::ZERO)) },
    )
    .await;

    assert_eq!(result, None);
}

#[tokio::test]
async fn max_affordable_treats_quote_error_as_ceiling() {
    // The fee quote errors once the contract exceeds what the balance can fund,
    // exactly as real note selection does. The solver must treat that as the
    // ceiling rather than overestimating.
    let cap = 400_000;
    let balance = Amount::from_msats(1_000_000);

    let result = max_affordable_send_amount(
        balance,
        Amount::from_msats(1),
        balance,
        |invoice| invoice,
        move |contract: Amount| async move {
            if contract.msats > cap {
                Err(anyhow::anyhow!("insufficient funds"))
            } else {
                Ok(federation_fee(Amount::ZERO))
            }
        },
    )
    .await;

    assert_eq!(result, Some(Amount::from_msats(cap)));
}

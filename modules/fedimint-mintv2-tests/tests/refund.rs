use std::collections::HashSet;
use std::time::Duration;

use fedimint_client::ClientHandleArc;
use fedimint_client::transaction::{TransactionBuilder, TxSubmissionStates, TxSubmissionStatesSM};
use fedimint_core::Amount;
use fedimint_core::core::OperationId;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_mintv2_client::{ECash, FinalReceiveOperationState, MintClientInit, MintClientModule};
use fedimint_mintv2_server::MintInit;
use fedimint_testing::fixtures::Fixtures;

async fn settle(client: &ClientHandleArc, operation_id: OperationId) {
    tokio::time::timeout(
        Duration::from_secs(60),
        client.await_no_active_states(operation_id),
    )
    .await
    .expect("Refund recovery must settle without an unbounded retry loop");
}

async fn transaction_count(client: &ClientHandleArc, operation_id: OperationId) -> usize {
    let (active, inactive) = client.executor().get_operation_states(operation_id).await;
    assert!(active.is_empty());
    inactive
        .into_iter()
        .filter_map(|(state, _)| {
            let state = state.as_any().downcast_ref::<TxSubmissionStatesSM>()?;
            match &state.state {
                TxSubmissionStates::Accepted(txid) | TxSubmissionStates::Rejected(txid, _) => {
                    Some(*txid)
                }
                _ => None,
            }
        })
        .collect::<HashSet<_>>()
        .len()
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_spent_and_live_notes_recover_without_unbounded_refunds() -> anyhow::Result<()> {
    refund_recovery(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_note_recovery_with_existing_wallet_inventory() -> anyhow::Result<()> {
    refund_recovery(true).await
}

async fn fund(client: &ClientHandleArc) -> anyhow::Result<()> {
    let funding = OperationId::new_random();
    let dummy = client.get_first_module::<DummyClientModule>()?;
    let range = client
        .finalize_and_submit_transaction(
            funding,
            "fund mintv2 refund regression",
            |_| (),
            TransactionBuilder::new()
                .with_inputs(dummy.create_input(Amount::from_msats(1_000_000))),
        )
        .await?;
    client
        .await_primary_bitcoin_module_outputs(funding, range.into_iter().collect())
        .await?;
    settle(client, funding).await;
    Ok(())
}

async fn refund_recovery(existing_inventory: bool) -> anyhow::Result<()> {
    let fixtures =
        Fixtures::new_primary(MintClientInit, MintInit).with_module(DummyClientInit, DummyInit);
    let fed = fixtures.new_fed_degraded().await;
    let sender = fed.new_client().await;
    let spender = fed.new_client().await;
    let receiver = fed.new_client().await;
    let invalid_receiver = fed.new_client().await;

    fund(&sender).await?;
    if existing_inventory {
        fund(&receiver).await?;
    }
    let initial_balance = receiver.get_balance_for_btc().await?;

    let (_, ecash) = sender
        .get_first_module::<MintClientModule>()?
        .send(
            Amount::from_msats((1 << 18) + (1 << 17)),
            serde_json::Value::Null,
            false,
        )
        .await?;
    let notes = ecash.notes();
    assert!(notes.len() > 1);
    let spent = ECash::new(ecash.mint().unwrap(), vec![notes[0].clone()]);
    let live_amount = notes
        .iter()
        .skip(1)
        .map(|note| note.amount())
        .sum::<Amount>();
    let spender_mint = spender.get_first_module::<MintClientModule>()?;
    let spend = spender_mint
        .receive(spent.clone(), serde_json::Value::Null)
        .await?;
    assert_eq!(
        spender_mint
            .await_final_receive_operation_state(spend)
            .await?,
        FinalReceiveOperationState::Success
    );
    settle(&spender, spend).await;

    // The original receive and aggregate refund both contain a spent nonce.
    // Recovery must split the failed bundle and settle the remaining live notes.
    let receiver_mint = receiver.get_first_module::<MintClientModule>()?;
    let receive = receiver_mint
        .receive(ecash.clone(), serde_json::Value::Null)
        .await?;
    assert_eq!(
        receiver_mint
            .await_final_receive_operation_state(receive)
            .await?,
        FinalReceiveOperationState::Rejected
    );
    settle(&receiver, receive).await;
    let recovered = receiver.get_balance_for_btc().await?;
    assert!(recovered > initial_balance);
    assert!(recovered <= initial_balance + live_amount);
    // With inventory, normal primary-module rebalancing can add funding inputs
    // with their own recovery transactions. The empty-wallet case isolates the
    // exact bound for the external notes.
    if !existing_inventory {
        assert_eq!(transaction_count(&receiver, receive).await, 2 + notes.len());
    }

    // An already-spent singleton must stop after one refund rejection. In
    // particular it cannot continuously create fresh random issuance outputs.
    let receive = invalid_receiver
        .get_first_module::<MintClientModule>()?
        .receive(spent, serde_json::Value::Null)
        .await?;
    settle(&invalid_receiver, receive).await;
    assert_eq!(invalid_receiver.get_balance_for_btc().await?, Amount::ZERO);
    assert_eq!(transaction_count(&invalid_receiver, receive).await, 2);
    Ok(())
}

use std::sync::Arc;

use anyhow::bail;
use fedimint_client::transaction::{ClientInput, ClientOutput, TransactionBuilder};
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::config::ClientModuleConfig;
use fedimint_core::core::{IntoDynInstance, ModuleKind, OperationId};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{sats, Amount, OutPoint};
use fedimint_dummy_client::states::DummyStateMachine;
use fedimint_dummy_client::{DummyClientGen, DummyClientModule};
use fedimint_dummy_common::config::{DummyClientConfig, DummyGenParams};
use fedimint_dummy_common::{broken_fed_key_pair, DummyInput, DummyOutput, KIND};
use fedimint_dummy_server::DummyGen;
use fedimint_testing::fixtures::Fixtures;
use secp256k1::Secp256k1;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_print_and_send_money() -> anyhow::Result<()> {
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;

    let (client1_dummy_module, _instance) = client1.get_first_module::<DummyClientModule>();
    let (client2_dummy_module, _instance) = client2.get_first_module::<DummyClientModule>();
    let (_, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1_dummy_module.receive_money(outpoint).await?;
    assert_eq!(client1.get_balance().await, sats(1000));

    let outpoint = client1_dummy_module
        .send_money(client2_dummy_module.account(), sats(250))
        .await?;
    client2_dummy_module.receive_money(outpoint).await?;
    assert_eq!(client1.get_balance().await, sats(750));
    assert_eq!(client2.get_balance().await, sats(250));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn can_threshold_sign_message() {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;
    let (dummy_module, _instance) = client.get_first_module::<DummyClientModule>();

    let message = "Hello fed!";
    let sig = dummy_module.fed_signature(message).await.unwrap();
    assert!(dummy_module.fed_public_key().verify(&sig, message));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_ignores_unknown_module() {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;

    let mut cfg = client.get_config().clone();
    let module_id = 2142;
    let extra_mod = ClientModuleConfig::from_typed(
        module_id,
        ModuleKind::from_static_str("unknown_module"),
        ModuleConsensusVersion(0),
        DummyClientConfig {
            tx_fee: Amount::from_sats(1),
            fed_public_key: threshold_crypto::SecretKey::random().public_key(),
        },
    )
    .unwrap();
    cfg.modules.insert(2142, extra_mod);

    // Test that building the client worked
    let _client = fed.new_client_with_config(cfg).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn federation_should_abort_if_balance_sheet_is_negative() -> anyhow::Result<()> {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;

    let (panic_sender, panic_receiver) = std::sync::mpsc::channel::<()>();
    let prev_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let panic_str = info.to_string();
        if panic_str
            .contains("Balance sheet of the fed has gone negative, this should never happen!")
        {
            // The first panic may lead to the receiver being dropped, so we have to swallow
            // the error here
            let _ = panic_sender.send(());
        }

        prev_panic_hook(info);
    }));

    let (_dummy, instance) = client.get_first_module::<DummyClientModule>();
    let op_id = OperationId(rand::random());
    let account_kp = broken_fed_key_pair();
    let input = ClientInput {
        input: DummyInput {
            amount: sats(1000),
            account: account_kp.x_only_public_key().0,
        },
        keys: vec![account_kp],
        state_machines: Arc::new(move |_, _| Vec::<DummyStateMachine>::new()),
    };

    let tx = TransactionBuilder::new().with_input(input.into_dyn(instance.id));
    let outpoint = |txid, _| OutPoint { txid, out_idx: 0 };
    client
        .finalize_and_submit_transaction(op_id, KIND.as_str(), outpoint, tx)
        .await?;

    // Make sure we panicked with the right message
    panic_receiver.recv().expect("Sender not dropped");

    Ok(())
}

/// A proper transaction is balanced, which means the sum of its inputs and
/// outputs are the same.
/// In this case we create a transaction with zero inputs and one output, which
/// the federation should reject because it's unbalanced.
#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> anyhow::Result<()> {
    let fed = fixtures().new_fed().await;
    let client = fed.new_client().await;

    let (dummy_module, instance) = client.get_first_module::<DummyClientModule>();
    let output = ClientOutput {
        output: DummyOutput {
            amount: sats(1000),
            account: dummy_module.account(),
        },
        state_machines: Arc::new(move |_, _| Vec::<DummyStateMachine>::new()),
    };
    let tx = TransactionBuilder::new().with_output(output.into_dyn(instance.id));
    let (tx, _) = tx.build(&Secp256k1::new(), rand::thread_rng());
    let result = client.api().submit_transaction(tx).await;
    match result {
        Ok(_) => bail!("Should have failed"),
        Err(e) if e.to_string().contains("The transaction is unbalanced") => Ok(()),
        Err(e) => bail!("Unexpected error: {e:?}"),
    }
}

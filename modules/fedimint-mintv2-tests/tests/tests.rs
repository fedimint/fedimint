use anyhow::ensure;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_core::Amount;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_mintv2_client::{ECash, MintClientInit, MintClientModule};
use fedimint_mintv2_server::MintInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use serde_json::Value;

const SEND_SK: [u8; 64] = [0x42; 64];
const RECEIVE_SK: [u8; 64] = [0x69; 64];

fn root_secret(bytes: &[u8; 64]) -> RootSecret {
    RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(bytes))
}

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);

    fixtures.with_module(DummyClientInit, DummyInit)
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;

    let client_send = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&SEND_SK))
        .await;

    let client_receive = fed
        .join_client_with_db(MemDatabase::new().into(), root_secret(&RECEIVE_SK))
        .await;

    let (op, outpoint) = client_send
        .get_first_module::<DummyClientModule>()?
        .print_money(Amount::from_sats(11_000))
        .await?;

    client_send
        .await_primary_bitcoin_module_outputs(op, vec![outpoint])
        .await?;

    for i in 0..10 {
        tracing::info!("Sending ecash payment {i} of 10");

        let ecash = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), None, false, Value::Null)
            .await?;

        let ecash = ecash.encode_base32();

        let ecash = ECash::decode_base32(&ecash).unwrap();

        let amount = client_receive
            .get_first_module::<MintClientModule>()?
            .receive(ecash, false, Value::Null)
            .await?;

        assert_eq!(amount.msats / 1_000, 1_000);

        test_client_recovery(&fed, &client_send, root_secret(&SEND_SK)).await?;
        test_client_recovery(&fed, &client_receive, root_secret(&RECEIVE_SK)).await?;
    }

    ensure!(client_receive.get_balance_for_btc().await? >= Amount::from_sats(9900));

    Ok(())
}

async fn test_client_recovery(
    fed: &FederationTest,
    client: &ClientHandleArc,
    root_secret: RootSecret,
) -> anyhow::Result<()> {
    let expected_balance = client.get_balance_for_btc().await?;

    assert_ne!(expected_balance, Amount::ZERO);

    let db = MemDatabase::new().into();

    let recovering_client = fed.recover_client_with_db(db, root_secret.clone()).await;

    recovering_client.wait_for_all_recoveries().await?;

    // After recovery completes, we need to reopen the client for modules to be
    // available. This is documented behavior - see gateway's client.rs:94-97
    let recovered_client = fed
        .open_client_with_db(recovering_client.db().clone(), root_secret)
        .await;

    // Wait for state machines to complete (they fetch signatures and write notes)
    recovered_client
        .wait_for_all_active_state_machines()
        .await?;

    let recovered_balance = recovered_client.get_balance_for_btc().await?;

    ensure!(
        recovered_balance == expected_balance,
        "Recovery balance mismatch: expected {expected_balance}, got {recovered_balance}"
    );

    Ok(())
}

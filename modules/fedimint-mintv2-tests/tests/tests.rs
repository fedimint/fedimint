use anyhow::ensure;
use fedimint_core::config::EmptyGenParams;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::Amount;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_mintv2_client::{ECash, MintClientInit, MintClientModule};
use fedimint_mintv2_common::config::{FeeConsensus, MintGenParams, MintGenParamsConsensus};
use fedimint_mintv2_server::MintInit;
use fedimint_testing::fixtures::Fixtures;
use serde_json::Value;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(
        MintClientInit,
        MintInit,
        MintGenParams {
            consensus: MintGenParamsConsensus {
                fee_consensus: FeeConsensus::new(1_000).expect("Relative fee is within range"),
            },
            local: EmptyGenParams {},
        },
    );

    fixtures.with_module(DummyClientInit, DummyInit, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn send_and_receive() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_default_fed().await;

    let (client_send, client_receive) = fed.two_clients().await;

    let (op, outpoint) = client_send
        .get_first_module::<DummyClientModule>()?
        .print_money(Amount::from_sats(11_000))
        .await?;

    client_send
        .await_primary_module_output(op, outpoint)
        .await?;

    for _ in 0..8 {
        let denominations = client_send
            .get_first_module::<MintClientModule>()?
            .get_count_by_denomination()
            .await;

        for (amount, count) in denominations.iter() {
            tracing::info!("Denominations: {amount} - {count}");
        }

        let ecash = client_send
            .get_first_module::<MintClientModule>()?
            .send(Amount::from_sats(1_000), None, false, Value::Null)
            .await?;

        let ecash = ecash.encode_base58();

        tracing::info!("{ecash}");

        let ecash = ECash::decode_base58(&ecash).unwrap();

        let amount = client_receive
            .get_first_module::<MintClientModule>()?
            .receive(ecash, false, Value::Null)
            .await?;

        assert_eq!(amount.msats / 1_000, 1_000);
    }

    retry(
        "Waiting for the full balance to become available".to_string(),
        backoff_util::background_backoff(),
        || async {
            ensure!(client_receive.get_balance().await >= Amount::from_sats(7900));

            Ok(())
        },
    )
    .await?;

    Ok(())
}

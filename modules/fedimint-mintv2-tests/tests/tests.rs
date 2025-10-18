use std::collections::BTreeSet;

use anyhow::ensure;
use fedimint_client::ClientHandleArc;
use fedimint_core::config::EmptyGenParams;
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
    let fed = fixtures.new_fed_not_degraded().await;

    let (client_send, client_receive) = fed.two_clients().await;

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

        test_recover_ecash(&client_send).await?;
        test_recover_ecash(&client_receive).await?;
    }

    ensure!(client_receive.get_balance_for_btc().await? >= Amount::from_sats(9900));

    Ok(())
}

async fn test_recover_ecash(client: &ClientHandleArc) -> anyhow::Result<()> {
    let requests = client
        .get_first_module::<MintClientModule>()?
        .recover_ecash()
        .await?;

    let tweaks = requests
        .iter()
        .map(|request| request.tweak)
        .collect::<BTreeSet<[u8; 12]>>();

    ensure!(tweaks.len() == requests.len());

    let recovered_balance = requests
        .iter()
        .map(|request| request.denomination.amount())
        .sum::<Amount>();

    ensure!(recovered_balance == client.get_balance_for_btc().await?);

    Ok(())
}

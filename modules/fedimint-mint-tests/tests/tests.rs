use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_mint_client::{
    MintClientExt, MintClientGen, OOBMaxOverpay, ReissueExternalNotesState, SpendOOBState,
};
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientGen, MintGen, MintGenParams::default());
    fixtures.with_module(DummyClientGen, DummyGen, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let (op, outpoint) = client1.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let (op, notes) = client1
        .spend_notes(sats(750), OOBMaxOverpay::Any, TIMEOUT, ())
        .await?;
    let sub1 = &mut client1.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    let op = client2.reissue_external_notes(notes, ()).await?;
    let sub2 = client2.subscribe_reissue_external_notes(op).await?;
    let mut sub2 = sub2.into_stream();
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Created);
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Issuing);
    assert_eq!(sub2.ok().await?, ReissueExternalNotesState::Done);
    assert_eq!(sub1.ok().await?, SpendOOBState::Success);

    assert_eq!(client1.get_balance().await, sats(250));
    assert_eq!(client2.get_balance().await, sats(750));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn oob_ecash_send_fails_if_wrong_denominations() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let (op, outpoint) = client1.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    loop {
        match client1
            .spend_notes(
                Amount::from_msats(64),
                OOBMaxOverpay::Limit {
                    max_rel: 0.1,
                    allow_below_abs: Amount::ZERO,
                },
                TIMEOUT,
                (),
            )
            .await
        {
            Ok((_op_id, notes)) => {
                assert!(notes.total_amount().msats < 71, "Overpaid by more than 10%");
            }
            Err(e) => {
                assert!(
                    e.to_string().contains("Would have overpaid"),
                    "Expected overpayment error, got `{e:?}`"
                );
                break;
            }
        }
    }

    Ok(())
}

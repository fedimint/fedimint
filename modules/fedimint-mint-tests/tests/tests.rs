use fedimint_core::sats;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_mint_client::{
    MintClientExt, MintClientGen, ReissueExternalNotesState, SpendOOBState,
};
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintGen;
use fedimint_testing::fixtures::{next, Fixtures, TIMEOUT};

fn fixtures() -> Fixtures {
    Fixtures::new()
        .with_primary(0, MintClientGen, MintGen, MintGenParams::default())
        .with_module(1, DummyClientGen, DummyGen, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let (op, outpoint) = client1.print_money(sats(1000)).await?;
    client1
        .await_primary_module_output_finalized(op, outpoint)
        .await?;

    // Spend from client1 to client2
    let (op, notes) = client1.spend_notes(sats(750), TIMEOUT, ()).await?;
    let sub1 = &mut client1
        .subscribe_spend_notes_updates(op)
        .await?
        .into_stream();
    assert_eq!(next(sub1).await, SpendOOBState::Created);

    let op = client2.reissue_external_notes(notes, ()).await?;
    let sub2 = &mut client2
        .subscribe_reissue_external_notes_updates(op)
        .await?
        .into_stream();
    assert_eq!(next(sub2).await, ReissueExternalNotesState::Created);
    assert_eq!(next(sub2).await, ReissueExternalNotesState::Issuing);
    assert_eq!(next(sub2).await, ReissueExternalNotesState::Done);
    assert_eq!(next(sub1).await, SpendOOBState::Success);

    assert_eq!(client1.total_amount().await, sats(250));
    assert_eq!(client2.total_amount().await, sats(750));
    Ok(())
}

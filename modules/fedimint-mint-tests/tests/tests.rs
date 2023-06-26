use fedimint_core::sats;
use fedimint_core::util::NextOrPending;
use fedimint_dummy_client::{DummyClientExt, DummyClientGen};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_mint_client::{
    MintClientExt, MintClientGen, ReissueExternalNotesState, SpendOOBState,
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
    let (op, notes) = client1.spend_notes(sats(750), TIMEOUT, ()).await?;
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

use std::io::Cursor;

use fedimint_client::backup::{ClientBackup, Metadata};
use fedimint_core::util::NextOrPending;
use fedimint_core::{sats, Amount};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_mint_client::{
    MintClientInit, MintClientModule, OOBNotes, ReissueExternalNotesState, SpendOOBState,
};
use fedimint_mint_common::config::MintGenParams;
use fedimint_mint_server::MintInit;
use fedimint_testing::fixtures::{Fixtures, TIMEOUT};

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit, MintGenParams::default());
    fixtures.with_module(DummyClientInit, DummyInit, DummyGenParams::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_ecash_out_of_band() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let client1_mint = client1.get_first_module::<MintClientModule>();
    let client2_mint = client2.get_first_module::<MintClientModule>();
    let (op, notes) = client1_mint.spend_notes(sats(750), TIMEOUT, ()).await?;
    let sub1 = &mut client1_mint.subscribe_spend_notes(op).await?.into_stream();
    assert_eq!(sub1.ok().await?, SpendOOBState::Created);

    let op = client2_mint.reissue_external_notes(notes, ()).await?;
    let sub2 = client2_mint.subscribe_reissue_external_notes(op).await?;
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
async fn backup_encode_decode_roundtrip() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    let backup = client1.create_backup(Metadata::empty()).await?;

    let backup_bin = fedimint_core::encoding::Encodable::consensus_encode_to_vec(&backup);

    let backup_decoded: ClientBackup = fedimint_core::encoding::Decodable::consensus_decode(
        &mut Cursor::new(&backup_bin),
        client1.decoders(),
    )
    .expect("decode");

    assert_eq!(backup, backup_decoded);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_spend() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()
        .spend_notes(Amount::ZERO, TIMEOUT, ())
        .await
        .expect_err("Zero-amount spends should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn error_zero_value_oob_receive() -> anyhow::Result<()> {
    // Print notes for client1
    let fed = fixtures().new_fed().await;
    let (client1, _client2) = fed.two_clients().await;
    let client1_dummy_module = client1.get_first_module::<DummyClientModule>();
    let (op, outpoint) = client1_dummy_module.print_money(sats(1000)).await?;
    client1.await_primary_module_output(op, outpoint).await?;

    // Spend from client1 to client2
    let err_msg = client1
        .get_first_module::<MintClientModule>()
        .reissue_external_notes(
            OOBNotes::new(client1.federation_id().to_prefix(), Default::default()),
            (),
        )
        .await
        .expect_err("Zero-amount receives should be forbidden")
        .to_string();
    assert!(err_msg.contains("zero-amount"));

    Ok(())
}

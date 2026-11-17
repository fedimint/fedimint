use assert_matches::assert_matches;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::sats;
use fedimint_eventlog::{Event, EventLogIdPrefixAll, UnorderedEventLogIdPrefixAll};
use fedimint_mint_client::events::{OOBNotesReissued, ReceivePaymentEvent};
use fedimint_mint_client::{
    MintClientModule, ReissueExternalNotesError, SelectNotesWithAtleastAmount,
};
use fedimint_mint_common::KIND;
use futures::StreamExt;

use super::{fixtures, issue_ecash};

#[tokio::test(flavor = "multi_thread")]
async fn reissue_records_both_start_events_without_duplicates() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_degraded().await;
    let (sender, receiver) = fed.two_clients().await;
    issue_ecash(&sender, sats(1000)).await?;
    let (_, notes) = sender
        .get_first_module::<MintClientModule>()?
        .spend_notes_with_selector(&SelectNotesWithAtleastAmount, sats(500), None, false, ())
        .await?;
    let amount = notes.total_amount();
    let mint = receiver.get_first_module::<MintClientModule>()?;
    let operation_id = mint.reissue_external_notes(notes.clone(), ()).await?;
    assert_matches!(
        mint.reissue_external_notes(notes, ()).await,
        Err(ReissueExternalNotesError::AlreadyReissued)
    );

    // The ordering task can move events between queues. Read both from one
    // snapshot so that neither a missing event nor a duplicate can be hidden.
    let mut dbtx = receiver.db().begin_transaction_nc().await;
    let mut events = dbtx
        .find_by_prefix(&EventLogIdPrefixAll)
        .await
        .map(|(_, event)| event)
        .collect::<Vec<_>>()
        .await;
    events.extend(
        dbtx.find_by_prefix(&UnorderedEventLogIdPrefixAll)
            .await
            .map(|(_, event)| event.inner)
            .collect::<Vec<_>>()
            .await,
    );
    let reissued = events
        .iter()
        .filter(|entry| entry.kind == OOBNotesReissued::KIND)
        .collect::<Vec<_>>();
    assert_eq!(reissued.len(), 1);
    let reissued = reissued[0]
        .to_event::<OOBNotesReissued>()
        .expect("reissue event decodes");
    assert_eq!(reissued.amount, amount);
    let receives = events
        .iter()
        .filter(|entry| entry.kind == ReceivePaymentEvent::KIND)
        .collect::<Vec<_>>();
    assert_eq!(receives.len(), 1);
    let receive = receives[0]
        .to_event::<ReceivePaymentEvent>()
        .expect("receive event decodes");
    assert_eq!(receive.operation_id, operation_id);
    assert_eq!(receive.amount, amount);
    for entry in events.iter().filter(|entry| {
        entry.kind == OOBNotesReissued::KIND || entry.kind == ReceivePaymentEvent::KIND
    }) {
        assert_eq!(entry.module_kind(), Some(&KIND));
        assert_eq!(entry.module_id(), Some(mint.id));
    }
    Ok(())
}

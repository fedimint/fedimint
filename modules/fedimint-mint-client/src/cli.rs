use std::collections::BTreeMap;
use std::time::Duration;
use std::{ffi, iter};

use anyhow::bail;
use clap::Parser;
use fedimint_core::{Amount, TieredMulti};
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::{
    MintClientModule, OOBNotes, ReissueExternalNotesState, SelectNotesWithAtleastAmount,
    SelectNotesWithExactAmount,
};

#[derive(Parser, Serialize)]
enum Opts {
    /// Reissue out of band notes
    Reissue { notes: OOBNotes },
    /// Prepare notes to send to a third party as a payment
    Spend {
        /// The amount of e-cash to spend
        amount: Amount,
        /// If the exact amount cannot be represented, return e-cash of a higher
        /// value instead of failing
        #[clap(long)]
        allow_overpay: bool,
        /// After how many seconds we will try to reclaim the e-cash if it
        /// hasn't been redeemed by the recipient. Defaults to one week.
        #[clap(long, default_value_t = 60 * 60 * 24 * 7)]
        timeout: u64,
        /// If the necessary information to join the federation the e-cash
        /// belongs to should be included in the serialized notes
        #[clap(long)]
        include_invite: bool,
    },
    /// Splits a string containing multiple e-cash notes (e.g. from the `spend`
    /// command) into ones that contain exactly one.
    Split { oob_notes: OOBNotes },
    /// Combines two or more serialized e-cash notes strings
    Combine {
        #[clap(required = true)]
        oob_notes: Vec<OOBNotes>,
    },
    /// Verifies the signatures of e-cash notes, if the online flag is specified
    /// it also checks with the mint if the notes were already spent
    Validate {
        /// Whether to check with the mint if the notes were already spent
        /// (CAUTION: this hurts privacy)
        #[clap(long)]
        online: bool,
        /// E-Cash note to validate
        oob_notes: OOBNotes,
    },
}

async fn spend(
    mint: &MintClientModule,
    amount: Amount,
    allow_overpay: bool,
    timeout: u64,
    include_invite: bool,
) -> anyhow::Result<serde_json::Value> {
    warn!(
        "The client will try to double-spend these notes after the timeout to reclaim \
        any unclaimed e-cash."
    );

    let timeout = Duration::from_secs(timeout);
    let (operation, notes) = if allow_overpay {
        let (operation, notes) = mint
            .spend_notes_with_selector(
                &SelectNotesWithAtleastAmount,
                amount,
                timeout,
                include_invite,
                (),
            )
            .await?;

        let overspend_amount = notes.total_amount().saturating_sub(amount);
        if overspend_amount != Amount::ZERO {
            warn!("Selected notes {overspend_amount} worth more than requested");
        }

        (operation, notes)
    } else {
        mint.spend_notes_with_selector(
            &SelectNotesWithExactAmount,
            amount,
            timeout,
            include_invite,
            (),
        )
        .await?
    };
    info!("Spend e-cash operation: {}", operation.fmt_short());

    Ok(json!({ "notes": notes }))
}

fn split(oob_notes: &OOBNotes) -> serde_json::Value {
    let federation = oob_notes.federation_id_prefix();
    let notes = oob_notes
        .notes()
        .iter()
        .map(|(amount, notes)| {
            let notes = notes
                .iter()
                .map(|note| {
                    OOBNotes::new(
                        federation,
                        TieredMulti::new(vec![(amount, vec![*note])].into_iter().collect()),
                    )
                })
                .collect::<Vec<_>>();
            (amount, notes)
        })
        .collect::<BTreeMap<_, _>>();

    json!({ "notes": notes })
}

fn combine(oob_notes: &[OOBNotes]) -> anyhow::Result<serde_json::Value> {
    let federation_id_prefix = {
        let mut prefixes = oob_notes.iter().map(OOBNotes::federation_id_prefix);
        let first = prefixes
            .next()
            .expect("At least one e-cash notes string expected");
        for prefix in prefixes {
            if prefix != first {
                bail!("Trying to combine e-cash from different federations: {first} and {prefix}");
            }
        }
        first
    };

    let combined_notes = oob_notes
        .iter()
        .flat_map(|notes| notes.notes().iter_items().map(|(amt, note)| (amt, *note)))
        .collect();

    let combined_oob_notes = OOBNotes::new(federation_id_prefix, combined_notes);

    Ok(json!({ "notes": combined_oob_notes }))
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mint")).chain(args.iter()));

    match opts {
        Opts::Reissue { notes } => {
            let amount = notes.total_amount();

            let operation_id = mint.reissue_external_notes(notes, ()).await?;

            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let ReissueExternalNotesState::Failed(e) = update {
                    bail!("Reissue failed: {e}");
                }
            }

            Ok(serde_json::to_value(amount).expect("JSON serialization failed"))
        }
        Opts::Spend {
            amount,
            allow_overpay,
            timeout,
            include_invite,
        } => spend(mint, amount, allow_overpay, timeout, include_invite).await,
        Opts::Split { oob_notes } => Ok(split(&oob_notes)),
        Opts::Combine { oob_notes } => combine(&oob_notes),
        Opts::Validate { oob_notes, online } => {
            let amount = mint.validate_notes(&oob_notes)?;

            if online {
                let any_spent = mint.check_note_spent(&oob_notes).await?;
                Ok(json!({
                    "any_spent": any_spent,
                    "amount_msat": amount,
                }))
            } else {
                Ok(json!({ "amount_msat": amount }))
            }
        }
    }
}

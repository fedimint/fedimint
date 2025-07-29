use std::{ffi, iter};

use anyhow::bail;
use clap::Parser;
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;

use crate::{MintClientModule, OOBNotes, ReissueExternalNotesState};

#[derive(Parser, Serialize)]
enum Opts {
    /// Reissue out of band notes
    Reissue { notes: OOBNotes },
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
        Opts::Validate { oob_notes, online } => {
            let amount = mint.validate_notes(&oob_notes)?;

            if online {
                let any_spent = mint.check_note_spent(&oob_notes).await?;
                Ok(json!({
                    "any_spent": any_spent,
                    "amount_msat": amount,
                }))
            } else {
                Ok(json!({
                    "amount_msat": amount,
                }))
            }
        }
    }
}

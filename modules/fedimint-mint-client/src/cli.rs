use std::{ffi, iter};

use anyhow::{bail, ensure};
use clap::Parser;
use fedimint_core::{Amount, TieredCounts};
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;

use crate::{MintClientModule, OOBNotes, ReissueExternalNotesState, SpendExactState};

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
    /// Spend notes with exact denominations and output them as OOB notes
    SpendExact {
        /// Comma-separated list of denominations to spend (e.g., "1,1,2,8")
        denominations: String,
        /// Include federation invite code in the OOB notes
        #[clap(long, default_value = "false")]
        include_invite: bool,
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
        Opts::SpendExact {
            denominations,
            include_invite,
        } => {
            // Parse denominations from string
            let denomination_counts =
                {
                    let mut denomination_counts = TieredCounts::default();

                    for denom_str in denominations.split(',') {
                        let amount =
                            Amount::from_msats(denom_str.trim().parse::<u64>().map_err(|_| {
                                anyhow::anyhow!("Invalid denomination: {}", denom_str)
                            })?);

                        // Check if denomination is supported
                        ensure!(
                            mint.cfg.tbs_pks.get(amount).is_some(),
                            "Denomination {} is not supported. Available denominations: {:?}",
                            amount,
                            mint.cfg.tbs_pks.tiers().collect::<Vec<_>>(),
                        );

                        denomination_counts.inc(amount, 1);
                    }

                    denomination_counts
                };

            if denomination_counts.is_empty() {
                bail!("No valid denominations provided");
            }

            // Start the spend operation
            let operation_id = mint
                .spend_notes_with_exact_denominations(denomination_counts, ())
                .await?;

            let notes = match mint
                .subscribe_spend_notes_with_exact_denominations(operation_id)
                .await?
                .await_outcome()
                .await
            {
                SpendExactState::Success(notes) => notes,
                SpendExactState::Failed(e) => {
                    bail!("Spend failed: {e}");
                }
                SpendExactState::Reissuing => {
                    unreachable!("Unexpected final state")
                }
            };

            // Convert to OOB notes
            let federation_id_prefix = mint.federation_id.to_prefix();
            let oob_notes = if include_invite {
                OOBNotes::new_with_invite(notes.clone(), &mint.client_ctx.get_invite_code().await)
            } else {
                OOBNotes::new(federation_id_prefix, notes.clone())
            };

            Ok(json!({
                "notes": oob_notes.to_string(),
                "amount_msat": notes.total_amount(),
            }))
        }
    }
}

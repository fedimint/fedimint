use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use std::{ffi, iter};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, PeerId, TieredMulti};
use futures::StreamExt;
use futures::future::join_all;
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::api::MintFederationApi;
use crate::{
    BlindNonce, MintClientModule, Nonce, OOBNotes, ReissueExternalNotesState,
    SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
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
    /// Debugging commands querying the federation directly
    Dev {
        #[clap(subcommand)]
        command: DevOpts,
    },
}

#[derive(Subcommand, Serialize)]
enum DevOpts {
    /// Ask every guardian if a note's nonce has already been spent
    ///
    /// Accepts either a hex-encoded nonce (33 byte compressed secp256k1 public
    /// key) or an out-of-band e-cash notes string, in which case every nonce it
    /// contains is checked.
    CheckNonce {
        /// Hex-encoded nonce or e-cash notes string
        nonce: String,
    },
    /// Ask every guardian if e-cash has already been issued for a blind nonce
    ///
    /// Accepts a hex-encoded blind nonce (48 byte compressed BLS12-381 G1
    /// point). Note that the human-readable form logged for a blind nonce is a
    /// SHA256 digest of it and can not be used here.
    CheckBlindNonce {
        /// Hex-encoded blind nonce
        blind_nonce: String,
    },
}

/// A single guardian's answer to a nonce or blind nonce query
#[derive(Serialize)]
#[serde(untagged)]
enum PeerCheckResult {
    Answer(bool),
    Error(String),
}

/// Asks every guardian if `nonce` was already spent.
///
/// Peers that fail to answer are reported as errors instead of failing the
/// whole query, since seeing the remaining guardians' answers is the point.
async fn check_nonce_spent(
    mint: &MintClientModule,
    nonce: Nonce,
) -> BTreeMap<PeerId, PeerCheckResult> {
    let api = mint.client_ctx.module_api();

    join_all(api.all_peers().iter().map(|&peer| {
        let api = &api;
        async move {
            let result = match api.check_note_spent_single_peer(peer, nonce).await {
                Ok(spent) => PeerCheckResult::Answer(spent),
                Err(e) => PeerCheckResult::Error(format!("error: {e}")),
            };
            (peer, result)
        }
    }))
    .await
    .into_iter()
    .collect()
}

/// Asks every guardian if e-cash was already issued for `blind_nonce`.
async fn check_blind_nonce_used(
    mint: &MintClientModule,
    blind_nonce: BlindNonce,
) -> BTreeMap<PeerId, PeerCheckResult> {
    let api = mint.client_ctx.module_api();

    join_all(api.all_peers().iter().map(|&peer| {
        let api = &api;
        async move {
            let result = match api
                .check_blind_nonce_used_single_peer(peer, blind_nonce)
                .await
            {
                Ok(used) => PeerCheckResult::Answer(used),
                Err(e) => PeerCheckResult::Error(format!("error: {e}")),
            };
            (peer, result)
        }
    }))
    .await
    .into_iter()
    .collect()
}

async fn check_nonce(mint: &MintClientModule, nonce: &str) -> anyhow::Result<serde_json::Value> {
    if let Ok(nonce) = Nonce::consensus_decode_hex(nonce, &ModuleDecoderRegistry::default()) {
        return Ok(json!({
            "nonce": nonce.consensus_encode_to_hex(),
            "spent": check_nonce_spent(mint, nonce).await,
        }));
    }

    let oob_notes = OOBNotes::from_str(nonce)
        .context("Argument is neither a hex-encoded nonce nor an e-cash notes string")?;

    let mut nonces = Vec::new();
    for (amount, note) in oob_notes.notes().iter_items() {
        let nonce = note.nonce();
        nonces.push(json!({
            "nonce": nonce.consensus_encode_to_hex(),
            "amount_msat": amount.msats,
            "spent": check_nonce_spent(mint, nonce).await,
        }));
    }

    Ok(json!({ "nonces": nonces }))
}

async fn check_blind_nonce(
    mint: &MintClientModule,
    blind_nonce: &str,
) -> anyhow::Result<serde_json::Value> {
    let blind_nonce =
        BlindNonce::consensus_decode_hex(blind_nonce, &ModuleDecoderRegistry::default())
            .context("Argument is not a hex-encoded blind nonce")?;

    Ok(json!({
        "blind_nonce": blind_nonce.consensus_encode_to_hex(),
        "issued": check_blind_nonce_used(mint, blind_nonce).await,
    }))
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
                Some(timeout),
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
            Some(timeout),
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
        Opts::Dev { command } => match command {
            DevOpts::CheckNonce { nonce } => check_nonce(mint, &nonce).await,
            DevOpts::CheckBlindNonce { blind_nonce } => check_blind_nonce(mint, &blind_nonce).await,
        },
    }
}

#[cfg(test)]
mod tests {
    use bls12_381::G1Affine;
    use tbs::BlindedMessage;

    use super::*;

    /// The hex `dev check-nonce` accepts is the plain compressed public key, so
    /// it matches what the JSON representation of a nonce shows.
    #[test]
    fn nonce_hex_round_trip() {
        let nonce_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let nonce = Nonce::consensus_decode_hex(nonce_hex, &ModuleDecoderRegistry::default())
            .expect("Valid compressed public key");

        assert_eq!(nonce.consensus_encode_to_hex(), nonce_hex);
    }

    /// Same for `dev check-blind-nonce` and the compressed G1 point.
    #[test]
    fn blind_nonce_hex_round_trip() {
        let blind_nonce = BlindNonce(BlindedMessage(G1Affine::generator()));
        let blind_nonce_hex = blind_nonce.consensus_encode_to_hex();

        assert_eq!(blind_nonce_hex.len(), 96);
        assert_eq!(
            BlindNonce::consensus_decode_hex(&blind_nonce_hex, &ModuleDecoderRegistry::default())
                .expect("Valid compressed G1 point"),
            blind_nonce
        );
    }
}

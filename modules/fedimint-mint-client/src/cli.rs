use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_api_client::api::FederationError;
use fedimint_core::config::FederationIdPrefix;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{Amount, PeerId, TieredMulti};
use futures::StreamExt;
use futures::future::join_all;
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::api::MintFederationApi;
use crate::{
    BlindNonce, MintClientModule, Nonce, OOBNotes, OOBNotesParseError, ReissueExternalNotesError,
    ReissueExternalNotesState, SelectNotesWithAtleastAmount, SelectNotesWithExactAmount,
    SpendOOBError, ValidateNotesError,
};

#[derive(Parser, Serialize)]
enum Opts {
    /// Reissue out of band notes
    Reissue {
        notes: Option<OOBNotes>,
        /// Read serialized notes from a file, or '-' for stdin.
        #[clap(long)]
        notes_file: Option<PathBuf>,
    },
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
    Split {
        oob_notes: Option<OOBNotes>,
        /// Read serialized notes from a file, or '-' for stdin.
        #[clap(long)]
        notes_file: Option<PathBuf>,
    },
    /// Combines two or more serialized e-cash notes strings
    Combine {
        oob_notes: Vec<OOBNotes>,
        /// Read one serialized notes string per file. May be repeated; '-'
        /// reads stdin once. Cannot be combined with positional notes.
        #[clap(long)]
        notes_file: Vec<PathBuf>,
    },
    /// Verifies the signatures of e-cash notes, if the online flag is specified
    /// it also checks with the mint if the notes were already spent
    Validate {
        /// Whether to check with the mint if the notes were already spent
        /// (CAUTION: this hurts privacy)
        #[clap(long)]
        online: bool,
        /// E-Cash note to validate
        oob_notes: Option<OOBNotes>,
        /// Read serialized notes from a file, or '-' for stdin.
        #[clap(long)]
        notes_file: Option<PathBuf>,
    },
    /// Debugging commands querying the federation directly
    Dev {
        #[clap(subcommand)]
        command: DevOpts,
    },
}

#[cfg(not(target_family = "wasm"))]
const MAX_NOTES_BYTES: usize = 16 * 1024 * 1024;

fn read_notes_file(path: &Path) -> Result<OOBNotes, CliCommandError> {
    #[cfg(not(target_family = "wasm"))]
    {
        let encoded = fedimint_core::util::read_secret_file(path, MAX_NOTES_BYTES)?;
        encoded
            .parse()
            .map_err(|_| CliCommandError::InvalidSecretNotes)
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = path;
        Err(CliCommandError::UnsupportedSecretInput)
    }
}

fn resolve_notes(
    notes: Option<OOBNotes>,
    file: Option<PathBuf>,
) -> Result<OOBNotes, CliCommandError> {
    match (notes, file) {
        (Some(notes), None) => Ok(notes),
        (None, Some(file)) => read_notes_file(&file),
        (Some(_), Some(_)) => Err(CliCommandError::ConflictingNotes),
        (None, None) => Err(CliCommandError::MissingNotes),
    }
}

fn resolve_notes_list(
    notes: Vec<OOBNotes>,
    files: &[PathBuf],
) -> Result<Vec<OOBNotes>, CliCommandError> {
    if !notes.is_empty() && !files.is_empty() {
        return Err(CliCommandError::ConflictingNotes);
    }
    if !notes.is_empty() {
        return Ok(notes);
    }
    if files.is_empty() {
        return Err(CliCommandError::MissingNotes);
    }
    #[cfg(not(target_family = "wasm"))]
    fedimint_core::util::ensure_single_stdin(files.iter().map(PathBuf::as_path))?;
    files.iter().map(|file| read_notes_file(file)).collect()
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
        nonce: Option<String>,
        /// Read serialized notes from a file, or '-' for stdin.
        #[clap(long)]
        notes_file: Option<PathBuf>,
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

fn resolve_nonce_argument(
    nonce: Option<String>,
    file: Option<PathBuf>,
) -> Result<String, CliCommandError> {
    match (nonce, file) {
        (Some(nonce), None) => Ok(nonce),
        (None, Some(file)) => Ok(read_notes_file(&file)?.to_string()),
        (Some(_), Some(_)) => Err(CliCommandError::ConflictingNonceArgument),
        (None, None) => Err(CliCommandError::MissingNonceArgument),
    }
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
                Err(e) => PeerCheckResult::Error(format!("error: {}", e.fmt_compact())),
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
                Err(e) => PeerCheckResult::Error(format!("error: {}", e.fmt_compact())),
            };
            (peer, result)
        }
    }))
    .await
    .into_iter()
    .collect()
}

async fn check_nonce(
    mint: &MintClientModule,
    nonce: &str,
) -> Result<serde_json::Value, CliCommandError> {
    if let Ok(nonce) = Nonce::consensus_decode_hex(nonce, &ModuleDecoderRegistry::default()) {
        return Ok(json!({
            "nonce": nonce.consensus_encode_to_hex(),
            "spent": check_nonce_spent(mint, nonce).await,
        }));
    }

    let oob_notes = OOBNotes::from_str(nonce).map_err(CliCommandError::InvalidNonceArgument)?;

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
) -> Result<serde_json::Value, CliCommandError> {
    let blind_nonce =
        BlindNonce::consensus_decode_hex(blind_nonce, &ModuleDecoderRegistry::default())
            .map_err(CliCommandError::InvalidBlindNonce)?;

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
) -> Result<serde_json::Value, CliCommandError> {
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

fn combine(oob_notes: &[OOBNotes]) -> Result<serde_json::Value, CliCommandError> {
    let federation_id_prefix = {
        let mut prefixes = oob_notes.iter().map(OOBNotes::federation_id_prefix);
        let first = prefixes
            .next()
            .expect("At least one e-cash notes string expected");
        for prefix in prefixes {
            if prefix != first {
                return Err(CliCommandError::MixedFederations {
                    first,
                    other: prefix,
                });
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
) -> Result<serde_json::Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mint")).chain(args.iter()));

    match opts {
        Opts::Reissue { notes, notes_file } => {
            let notes = resolve_notes(notes, notes_file)?;
            let amount = notes.total_amount();

            let operation_id = mint.reissue_external_notes(notes, ()).await?;

            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let ReissueExternalNotesState::Failed(e) = update {
                    return Err(CliCommandError::ReissueFailed(e));
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
        Opts::Split {
            oob_notes,
            notes_file,
        } => Ok(split(&resolve_notes(oob_notes, notes_file)?)),
        Opts::Combine {
            oob_notes,
            notes_file,
        } => combine(&resolve_notes_list(oob_notes, &notes_file)?),
        Opts::Validate {
            oob_notes,
            notes_file,
            online,
        } => {
            let oob_notes = resolve_notes(oob_notes, notes_file)?;
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
            DevOpts::CheckNonce { nonce, notes_file } => {
                check_nonce(mint, &resolve_nonce_argument(nonce, notes_file)?).await
            }
            DevOpts::CheckBlindNonce { blind_nonce } => check_blind_nonce(mint, &blind_nonce).await,
        },
    }
}

/// A failure of a `mint` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    #[error("Provide either positional nonce/notes or --notes-file, not both")]
    ConflictingNonceArgument,
    #[error("Provide positional nonce/notes or --notes-file")]
    MissingNonceArgument,
    #[error("Provide either positional notes or --notes-file, not both")]
    ConflictingNotes,
    #[error("Provide positional notes or --notes-file")]
    MissingNotes,
    #[cfg(not(target_family = "wasm"))]
    #[error("Invalid e-cash notes in secret input")]
    InvalidSecretNotes,
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    SecretInput(#[from] fedimint_core::util::SecretInputError),
    #[cfg(target_family = "wasm")]
    #[error("Secret file input is not supported on this platform")]
    UnsupportedSecretInput,
    /// The notes could not be reissued.
    #[error(transparent)]
    Reissue(#[from] ReissueExternalNotesError),

    /// The reissue transaction failed.
    #[error("Reissue failed: {0}")]
    ReissueFailed(String),

    /// The notes to spend could not be selected or prepared.
    #[error(transparent)]
    Spend(#[from] SpendOOBError),

    /// Notes of different federations were given to combine.
    #[error("Trying to combine e-cash from different federations: {first} and {other}")]
    MixedFederations {
        first: FederationIdPrefix,
        other: FederationIdPrefix,
    },

    /// The notes to validate are invalid.
    #[error(transparent)]
    Validate(#[from] ValidateNotesError),

    /// The federation could not say whether the notes are spent.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// The argument of `dev check-nonce` is neither a nonce nor e-cash.
    #[error("Argument is neither a hex-encoded nonce nor an e-cash notes string")]
    InvalidNonceArgument(#[source] OOBNotesParseError),

    /// The argument of `dev check-blind-nonce` is not a blind nonce.
    #[error("Argument is not a hex-encoded blind nonce")]
    InvalidBlindNonce(#[source] DecodeError),
}

#[cfg(test)]
mod tests;

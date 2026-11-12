use std::path::PathBuf;
use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_client_module::error::OperationLookupError;
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX, PrefixedDecodeError};
use fedimint_core::core::Account;
use serde::Serialize;
use serde_json::Value;

use crate::{ECash, MintClientModule, ReceiveECashError, SendECashError, SpendableNote};

#[derive(Parser, Serialize)]
enum Opts {
    /// Count the `ECash` notes an account holds by denomination.
    Count {
        #[clap(long, default_value_t = Account::Primary)]
        account: Account,
    },
    /// Send `ECash` for the given amount.
    Send {
        amount: Amount,
        #[clap(long, default_value_t = Account::Primary)]
        account: Account,
        /// Embed the federation's invite code in the serialized ecash so a
        /// recipient that hasn't joined the federation can do so from it.
        #[clap(long)]
        include_invite: bool,
    },
    /// Hand out everything an account holds as one bundle. Receive it into
    /// another account to move a balance across.
    SendMax {
        #[clap(long, default_value_t = Account::Primary)]
        account: Account,
        #[clap(long)]
        include_invite: bool,
    },
    /// Receive the `ECash` by reissuing the notes and return the amount.
    Receive {
        ecash: Option<String>,
        /// Read serialized e-cash from a file, or '-' for stdin.
        #[clap(long)]
        ecash_file: Option<PathBuf>,
        #[clap(long, default_value_t = Account::Primary)]
        account: Account,
    },
    /// Developer and debugging commands.
    Dev {
        #[clap(subcommand)]
        command: DevOpts,
    },
}

#[derive(Subcommand, Serialize)]
enum DevOpts {
    /// Decode an `ECash` string into a JSON representation without receiving
    /// it.
    Decode { ecash: String },
}

fn resolve_ecash(ecash: Option<String>, file: Option<PathBuf>) -> Result<ECash, CliCommandError> {
    match (ecash, file) {
        (Some(ecash), None) => Ok(base32::decode_prefixed(FEDIMINT_PREFIX, &ecash)?),
        (None, Some(file)) => {
            #[cfg(not(target_family = "wasm"))]
            {
                let encoded = fedimint_core::util::read_secret_file(&file, 16 * 1024 * 1024)?;
                base32::decode_prefixed(FEDIMINT_PREFIX, &encoded)
                    .map_err(|_| CliCommandError::InvalidSecretEcash)
            }
            #[cfg(target_family = "wasm")]
            {
                let _ = file;
                Err(CliCommandError::UnsupportedSecretInput)
            }
        }
        (Some(_), Some(_)) => Err(CliCommandError::ConflictingEcash),
        (None, None) => Err(CliCommandError::MissingEcash),
    }
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> Result<Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mintv2")).chain(args.iter()));

    match opts {
        Opts::Count { account } => Ok(json(mint.get_count_by_denomination(account).await)),
        Opts::Send {
            amount,
            account,
            include_invite,
        } => {
            let (_, ecash) = mint
                .send(account, amount, Value::Null, include_invite)
                .await?;
            let ecash = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash);

            Ok(json(ecash))
        }
        Opts::SendMax {
            account,
            include_invite,
        } => {
            let ecash = mint
                .send_max(account, Value::Null, include_invite)
                .await
                .map(|(_, ecash)| base32::encode_prefixed(FEDIMINT_PREFIX, &ecash));

            Ok(json(ecash))
        }
        Opts::Receive {
            ecash,
            ecash_file,
            account,
        } => {
            let ecash = resolve_ecash(ecash, ecash_file)?;

            let operation_id = mint.receive(account, ecash, Value::Null).await?;

            let state = mint
                .await_final_receive_operation_state(operation_id)
                .await?;

            Ok(json(state))
        }
        Opts::Dev {
            command: DevOpts::Decode { ecash },
        } => {
            let ecash: ECash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash)?;
            let notes = ecash.notes();

            Ok(serde_json::json!({
                "federation_id": ecash.mint(),
                "unit": ecash.unit(),
                "amount": ecash.amount(),
                "note_count": notes.len(),
                "notes": notes.iter().map(SpendableNote::note).collect::<Vec<_>>(),
                "invite": ecash.federation_invite(),
            }))
        }
    }
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

/// A failure of a `mintv2` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    #[error("Provide either positional e-cash or --ecash-file, not both")]
    ConflictingEcash,
    #[error("Provide positional e-cash or --ecash-file")]
    MissingEcash,
    #[cfg(not(target_family = "wasm"))]
    #[error("Invalid e-cash in secret input")]
    InvalidSecretEcash,
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    SecretInput(#[from] fedimint_core::util::SecretInputError),
    #[cfg(target_family = "wasm")]
    #[error("Secret file input is not supported on this platform")]
    UnsupportedSecretInput,
    /// The e-cash could not be sent.
    #[error(transparent)]
    Send(#[from] SendECashError),

    /// The e-cash string is not valid.
    #[error(transparent)]
    Decode(#[from] PrefixedDecodeError),

    /// The e-cash could not be received.
    #[error(transparent)]
    Receive(#[from] ReceiveECashError),

    /// The receive operation could not be looked up.
    #[error(transparent)]
    OperationLookup(#[from] OperationLookupError),
}

#[cfg(test)]
mod tests;

use std::{ffi, iter};

use clap::Parser;
use fedimint_client_module::error::OperationLookupError;
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX, PrefixedDecodeError};
use fedimint_core::core::ModuleInstanceId;
use serde::Serialize;
use serde_json::Value;

use crate::{ECash, MintClientModule, ReceiveECashError, SendECashError};

#[derive(Parser, Serialize)]
enum Opts {
    /// Count the `ECash` notes in the client's database by denomination.
    Count,
    /// Send `ECash` for the given amount.
    Send {
        amount: Amount,
        /// Embed the federation's invite code in the serialized ecash so a
        /// recipient that hasn't joined the federation can do so from it.
        #[clap(long)]
        include_invite: bool,
    },
    /// Receive the `ECash` by reissuing the notes and return the amount.
    Receive { ecash: String },
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> Result<Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mintv2")).chain(args.iter()));

    match opts {
        Opts::Count => Ok(json(mint.get_count_by_denomination().await)),
        Opts::Send {
            amount,
            include_invite,
        } => {
            let (_, ecash) = mint.send(amount, Value::Null, include_invite).await?;
            let ecash = base32::encode_prefixed(FEDIMINT_PREFIX, &ecash);

            Ok(json(ecash))
        }
        Opts::Receive { ecash } => {
            let ecash: ECash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash)?;

            match mint.receive(ecash.clone(), Value::Null).await {
                Ok(operation_id) => {
                    let state = mint
                        .await_final_receive_operation_state(operation_id)
                        .await?;

                    Ok(json(state))
                }
                Err(ReceiveECashError::WrongModuleInstance { actual, expected }) => {
                    Err(CliCommandError::WrongModuleInstance { actual, expected })
                }
                Err(e) => Err(CliCommandError::Receive(e)),
            }
        }
    }
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

/// A failure of a `mintv2` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    /// The e-cash could not be sent.
    #[error(transparent)]
    Send(#[from] SendECashError),

    /// The e-cash string is not valid.
    #[error(transparent)]
    Decode(#[from] PrefixedDecodeError),

    /// The e-cash could not be received.
    #[error(transparent)]
    Receive(#[from] ReceiveECashError),

    /// The e-cash was issued by a different module instance.
    /// The error includes the correct module instance id to use.
    #[error(
        "The ECash was issued by module instance {actual}, but this is module instance {expected}. Please try: fedimint-cli -m mintv2:{actual} receive <ecash>"
    )]
    WrongModuleInstance {
        /// The module instance that issued the e-cash.
        actual: ModuleInstanceId,
        /// The module instance that received the e-cash (incorrect).
        expected: ModuleInstanceId,
    },

    /// The receive operation could not be looked up.
    #[error(transparent)]
    OperationLookup(#[from] OperationLookupError),
}

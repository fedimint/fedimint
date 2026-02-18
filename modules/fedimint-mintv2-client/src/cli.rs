use std::{ffi, iter};

use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use serde::Serialize;
use serde_json::Value;

use crate::MintClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    /// Count the `ECash` notes in the client's database by denomination.
    Count,
    /// Send `ECash` for the given amount.
    Send { amount: Amount },
    /// Receive the `ECash` by reissuing the notes and return the amount.
    Receive { ecash: String },
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mintv2")).chain(args.iter()));

    match opts {
        Opts::Count => Ok(json(mint.get_count_by_denomination().await)),
        Opts::Send { amount } => {
            let ecash = mint
                .send(amount, Value::Null)
                .await
                .map(|ecash| base32::encode_prefixed(FEDIMINT_PREFIX, &ecash))?;

            Ok(json(ecash))
        }
        Opts::Receive { ecash } => {
            let ecash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash)?;

            let operation_id = mint.receive(ecash, Value::Null).await?;

            let state = mint.await_final_receive_operation_state(operation_id).await;

            Ok(json(state))
        }
    }
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

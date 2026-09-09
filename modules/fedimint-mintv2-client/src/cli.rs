use std::{ffi, iter};

use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::core::Account;
use serde::Serialize;
use serde_json::Value;

use crate::MintClientModule;

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
        ecash: String,
        #[clap(long, default_value_t = Account::Primary)]
        account: Account,
    },
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
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
        Opts::Receive { ecash, account } => {
            let ecash = base32::decode_prefixed(FEDIMINT_PREFIX, &ecash)?;

            let operation_id = mint.receive(account, ecash, Value::Null).await?;

            let state = mint
                .await_final_receive_operation_state(operation_id)
                .await?;

            Ok(json(state))
        }
    }
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

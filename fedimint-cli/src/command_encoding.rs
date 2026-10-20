use std::fs;
use std::str::FromStr;

use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::config::FederationIdPrefix;
use fedimint_core::db::DatabaseValue;
use fedimint_core::invite_code::InviteCode;
use fedimint_mint_client::OOBNotes;

use crate::cli::{DecodeType, EncodeType, OOBNotesJson, Opts};
use crate::{CliOutput, CliOutputResult, CliResultExt, FedimintCli};

impl FedimintCli {
    /// Decode local data, opening a client only for transaction module
    /// decoders.
    pub(super) async fn handle_decode(
        &mut self,
        cli: &Opts,
        decode_type: DecodeType,
    ) -> CliOutputResult {
        match decode_type {
            DecodeType::InviteCode { invite_code } => Ok(CliOutput::DecodeInviteCode {
                url: invite_code.url(),
                federation_id: invite_code.federation_id(),
            }),
            DecodeType::Notes { notes, file } => {
                let notes = if let Some(notes) = notes {
                    notes
                } else if let Some(file) = file {
                    let notes_str =
                        fs::read_to_string(file).map_err_cli_msg("failed to read file")?;
                    OOBNotes::from_str(&notes_str).map_err_cli_msg("failed to decode notes")?
                } else {
                    unreachable!("Clap enforces either notes or file being set");
                };
                let notes_json = notes
                    .notes_json()
                    .map_err_cli_msg("failed to decode notes")?;
                Ok(CliOutput::Raw(notes_json))
            }
            DecodeType::Transaction { hex_string } => {
                let bytes: Vec<u8> = hex::FromHex::from_hex(&hex_string)
                    .map_err_cli_msg("failed to decode transaction")?;
                let client = self.client_open(cli).await?;
                let tx =
                    fedimint_core::transaction::Transaction::from_bytes(&bytes, client.decoders())
                        .map_err_cli_msg("failed to decode transaction")?;
                Ok(CliOutput::DecodeTransaction {
                    transaction: format!("{tx:?}"),
                })
            }
            DecodeType::SetupCode { setup_code } => {
                let setup_code = base32::decode_prefixed(FEDIMINT_PREFIX, &setup_code)
                    .map_err_cli_msg("failed to decode setup code")?;
                Ok(CliOutput::SetupCode { setup_code })
            }
        }
    }
}

/// Encode portable client data without opening a database or network
/// connection.
pub(super) fn handle_encode(encode_type: EncodeType) -> CliOutputResult {
    match encode_type {
        EncodeType::InviteCode {
            url,
            federation_id,
            peer,
            api_secret,
        } => Ok(CliOutput::InviteCode {
            invite_code: InviteCode::new(url, peer, federation_id, api_secret),
        }),
        EncodeType::Notes { notes_json } => {
            let notes = serde_json::from_str::<OOBNotesJson>(&notes_json)
                .map_err_cli_msg("invalid JSON for notes")?;
            let prefix = FederationIdPrefix::from_str(&notes.federation_id_prefix).map_err_cli()?;
            let notes = OOBNotes::new(prefix, notes.notes);
            Ok(CliOutput::Raw(notes.to_string().into()))
        }
    }
}

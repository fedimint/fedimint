use std::str::FromStr;

use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::config::FederationIdPrefix;
use fedimint_core::db::DatabaseValue;
use fedimint_core::invite_code::InviteCode;
use fedimint_mint_client::OOBNotes;

use crate::cli::{DecodeType, EncodeType, OOBNotesJson, Opts};
use crate::{CliError, CliOutput, CliOutputResult, CliResultExt, FedimintCli};

impl FedimintCli {
    /// Decode local data, opening a client only for transaction module
    /// decoders.
    pub(super) async fn handle_decode(
        &mut self,
        cli: &Opts,
        decode_type: DecodeType,
    ) -> CliOutputResult {
        match decode_type {
            DecodeType::InviteCode { invite_code, .. } => {
                let invite_code =
                    InviteCode::from_str(&invite_code.expect("secret inputs were resolved"))
                        .map_err(|_| CliError {
                            error: "Invalid invite code".to_owned(),
                        })?;
                Ok(CliOutput::DecodeInviteCode {
                    url: invite_code.url(),
                    federation_id: invite_code.federation_id(),
                })
            }
            DecodeType::Notes { notes, .. } => {
                let notes = OOBNotes::from_str(&notes.expect("secret inputs were resolved"))
                    .map_err(|_| CliError {
                        error: "Invalid notes".to_owned(),
                    })?;
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
            ..
        } => Ok(CliOutput::InviteCode {
            invite_code: InviteCode::new(url, peer, federation_id, api_secret),
        }),
        EncodeType::Notes { notes_json, .. } => {
            let notes = serde_json::from_str::<OOBNotesJson>(
                &notes_json.expect("secret inputs were resolved"),
            )
            .map_err(|_| CliError {
                error: "Invalid JSON for notes".to_owned(),
            })?;
            let prefix =
                FederationIdPrefix::from_str(&notes.federation_id_prefix).map_err(|_| {
                    CliError {
                        error: "Invalid federation prefix in notes".to_owned(),
                    }
                })?;
            let notes = OOBNotes::new(prefix, notes.notes);
            Ok(CliOutput::Raw(notes.to_string().into()))
        }
    }
}

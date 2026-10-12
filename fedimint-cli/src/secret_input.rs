//! Resolve root protected inputs and preflight legacy sources before startup.
//!
//! Module handlers retain their existing parsing lifecycle, but their stdin
//! consumers are counted before any root input is read or the client is opened.

use std::path::{Path, PathBuf};

use anyhow::ensure;
use fedimint_core::util::{ensure_single_stdin, read_secret_file};

use crate::cli::{AdminCmd, Command, DecodeType, DevCmd, EncodeType, Opts};
use crate::client::ClientCmd;

const CREDENTIAL_LIMIT: usize = 1024 * 1024;
const PAYLOAD_LIMIT: usize = 16 * 1024 * 1024;

struct Source<'a> {
    value: &'a mut Option<String>,
    file: &'a Option<PathBuf>,
    required: bool,
    limit: usize,
}

impl<'a> Source<'a> {
    fn credential(
        value: &'a mut Option<String>,
        file: &'a Option<PathBuf>,
        required: bool,
    ) -> Self {
        Self {
            value,
            file,
            required,
            limit: CREDENTIAL_LIMIT,
        }
    }

    fn payload(value: &'a mut Option<String>, file: &'a Option<PathBuf>) -> Self {
        Self {
            value,
            file,
            required: true,
            limit: PAYLOAD_LIMIT,
        }
    }
}

impl Opts {
    pub(crate) fn resolve_secret_inputs(&mut self) -> anyhow::Result<()> {
        let notes_files: Vec<PathBuf> = if let Command::Client(command) = &self.command {
            command.validate_notes_sources()?;
            command
                .notes_file_paths()
                .into_iter()
                .map(Path::to_path_buf)
                .collect()
        } else {
            vec![]
        };
        let has_federation_secret =
            self.federation_secret_hex.is_some() || self.federation_secret_hex_file.is_some();
        if let Command::Client(ClientCmd::Restore {
            mnemonic,
            mnemonic_file,
            ..
        }) = &self.command
        {
            let has_mnemonic = mnemonic.is_some() || mnemonic_file.is_some();
            ensure!(
                has_mnemonic != has_federation_secret,
                "Restore requires exactly one mnemonic or federation secret input"
            );
        }
        ensure!(
            !has_federation_secret || !matches!(self.command, Command::Join { .. }),
            "A custom federation secret cannot be used with join"
        );
        let mut sources = vec![
            Source::credential(&mut self.password, &self.password_file, false),
            Source::credential(
                &mut self.federation_secret_hex,
                &self.federation_secret_hex_file,
                false,
            ),
        ];
        match &mut self.command {
            Command::Join {
                invite_code,
                invite_code_file,
            }
            | Command::Dev(
                DevCmd::QueryFederationIps {
                    invite_code,
                    invite_code_file,
                    ..
                }
                | DevCmd::Decode {
                    decode_type:
                        DecodeType::InviteCode {
                            invite_code,
                            invite_code_file,
                        },
                },
            ) => sources.push(Source::credential(invite_code, invite_code_file, true)),
            Command::Client(ClientCmd::Restore {
                mnemonic,
                mnemonic_file,
                invite_code,
                invite_code_file,
            }) => {
                sources.push(Source::credential(mnemonic, mnemonic_file, false));
                sources.push(Source::credential(invite_code, invite_code_file, true));
            }
            Command::Admin(AdminCmd::Auth {
                password,
                password_file,
                ..
            })
            | Command::Dev(
                DevCmd::ConfigDecrypt {
                    password,
                    password_file,
                    ..
                }
                | DevCmd::ConfigEncrypt {
                    password,
                    password_file,
                    ..
                },
            ) => sources.push(Source::credential(password, password_file, true)),
            Command::Dev(DevCmd::Api {
                password,
                password_file,
                params,
                params_file,
                ..
            }) => {
                sources.push(Source::credential(password, password_file, false));
                sources.push(Source {
                    value: params,
                    file: params_file,
                    required: false,
                    limit: PAYLOAD_LIMIT,
                });
            }
            Command::Dev(DevCmd::Decode {
                decode_type: DecodeType::Notes { notes, file },
            }) => sources.push(Source::payload(notes, file)),
            Command::Dev(DevCmd::Encode {
                encode_type:
                    EncodeType::Notes {
                        notes_json,
                        notes_json_file,
                    },
            }) => sources.push(Source::payload(notes_json, notes_json_file)),
            Command::Dev(DevCmd::Encode {
                encode_type:
                    EncodeType::InviteCode {
                        api_secret,
                        api_secret_file,
                        ..
                    },
            }) => sources.push(Source::credential(api_secret, api_secret_file, false)),
            _ => {}
        }
        // Validate all sources before opening any file or consuming stdin. Runtime
        // errors avoid clap diagnostics that could echo positional secret values.
        for source in &sources {
            ensure!(
                source.value.is_none() || source.file.is_none(),
                "A direct or environment input cannot be combined with its file input"
            );
            ensure!(
                !source.required || source.value.is_some() || source.file.is_some(),
                "Required input missing: supply a value or its file option"
            );
        }
        ensure_single_stdin(
            sources
                .iter()
                .filter_map(|source| source.file.as_deref())
                .chain(notes_files.iter().map(PathBuf::as_path)),
        )?;
        for source in sources {
            if let Some(path) = source.file {
                *source.value = Some(read_secret_file(path, source.limit)?);
            }
        }
        Ok(())
    }
}

/// Module arguments are parsed by the modules themselves, after the global CLI
/// options. Reserve their stdin before reading a global secret input.
pub(crate) fn check_module_stdin(opts: &Opts) -> anyhow::Result<()> {
    let Command::Client(ClientCmd::Module { args, .. }) = &opts.command else {
        return Ok(());
    };
    let mut stdin_inputs = [&opts.password_file, &opts.federation_secret_hex_file]
        .into_iter()
        .flatten()
        .filter(|path| *path == Path::new("-"))
        .count();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if arg == "--notes-file=-" || arg == "--ecash-file=-" {
            stdin_inputs += 1;
        }
        if (arg == "--notes-file" || arg == "--ecash-file")
            && args.next().is_some_and(|value| value == "-")
        {
            stdin_inputs += 1;
        }
    }
    ensure!(
        stdin_inputs <= 1,
        "Only one secret input may read standard input"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

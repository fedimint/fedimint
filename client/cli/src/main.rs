use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::{secp256k1, Address, Network, Transaction};
use clap::{Parser, Subcommand};
use fedimint_core::api::{
    FederationApiExt, GlobalFederationApi, IFederationApi, WsClientConnectInfo, WsFederationApi,
};
use fedimint_core::config::{load_from_file, ClientConfig, ModuleGenRegistry};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::DynModuleGen;
use fedimint_core::query::EventuallyConsistent;
use fedimint_core::task::TaskGroup;
use fedimint_core::{Amount, OutPoint, TieredMulti, TransactionId};
use fedimint_logging::TracingSetup;
use fedimint_mint::common::MintDecoder;
use fedimint_mint::MintGen;
use mint_client::mint::SpendableNote;
use mint_client::modules::ln::common::LightningDecoder;
use mint_client::modules::ln::contracts::ContractId;
use mint_client::modules::ln::LightningGen;
use mint_client::modules::wallet::common::WalletDecoder;
use mint_client::modules::wallet::txoproof::TxOutProof;
use mint_client::modules::wallet::WalletGen;
use mint_client::utils::{
    from_hex, parse_bitcoin_amount, parse_ecash, parse_fedimint_amount, parse_node_pub_key,
    serialize_ecash,
};
use mint_client::{module_decode_stubs, Client, UserClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize)]
#[serde(rename_all(serialize = "snake_case"))]
#[serde(untagged)]
enum CliOutput {
    VersionHash {
        hash: String,
    },

    UntypedApiOutput {
        value: Value,
    },

    PegInAddress {
        address: Address,
    },

    PegIn {
        id: TransactionId,
    },

    Reissue {
        id: OutPoint,
    },

    Validate {
        all_valid: bool,
        details: BTreeMap<Amount, usize>,
    },

    Spend {
        note: String,
    },

    PegOut {
        tx_id: bitcoin::Txid,
    },

    LnPay {
        contract_id: ContractId,
    },

    Fetch {
        issuance: Vec<OutPoint>,
    },

    Info {
        federation_id: String,
        federation_name: String,
        network: Network,
        total_amount: Amount,
        total_num_notes: usize,
        details: BTreeMap<Amount, usize>,
    },

    LnInvoice {
        invoice: lightning_invoice::Invoice,
    },

    WaitInvoice {
        paid_in_tx: OutPoint,
    },

    WaitBlockHeight {
        reached: u64,
    },

    ConnectInfo {
        connect_info: WsClientConnectInfo,
    },

    JoinFederation {
        joined: String,
    },

    ListGateways {
        num_gateways: usize,
        gateways: Value,
    },

    SwitchGateway {
        new_gateway: Value,
    },

    Backup,
}

impl fmt::Display for CliOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum CliErrorKind {
    NetworkError,
    IOError,
    InvalidValue,
    OSError,
    GeneralFederationError,
    AlreadySpent,
    Timeout,
    InsufficientBalance,
    SerializationError,
    GeneralFailure,
}

#[derive(Serialize)]
#[serde(tag = "error", rename_all(serialize = "snake_case"))]
struct CliError {
    kind: CliErrorKind,
    message: String,
    #[serde(skip_serializing)]
    raw_error: Option<Box<dyn Error>>,
}

impl Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("raw_error", &self.raw_error)
            .finish()
    }
}

impl CliError {
    fn from(kind: CliErrorKind, message: &str, err: Option<Box<dyn Error>>) -> CliError {
        CliError {
            kind: (kind),
            message: (String::from(message)),
            raw_error: err,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut json = serde_json::to_value(self).unwrap();
        if let Some(err) = &self.raw_error {
            json["raw_error"] = json!(*err.to_string())
        }
        write!(f, "{}", serde_json::to_string_pretty(&json).unwrap())
    }
}

impl Error for CliError {}

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// The working directory of the client containing the config and db
    #[arg(long = "workdir")]
    workdir: PathBuf,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
#[command(version)]
struct CliNoWorkdir {
    #[clap(subcommand)]
    command: CommandNoWorkdir,
}

#[derive(Subcommand)]
enum CommandNoWorkdir {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
}
#[derive(Subcommand)]
enum Command {
    /// Print the latest git commit hash this bin. was build with
    VersionHash,
    /// Generate a new peg-in address, funds sent to it can later be claimed
    PegInAddress,

    /// Send direct method call to the API, waiting for all peers to agree on a
    /// response
    Api {
        method: String,
        /// JSON args that will be serialized and send with the request
        #[clap(default_value = "null")]
        arg: String,
    },

    /// Issue notes in exchange for a peg-in proof
    PegIn {
        #[clap(value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },

    /// Reissue notes received from a third party to avoid double spends
    Reissue {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },

    /// Validate notes without claiming them (only checks if signatures valid,
    /// does not check if nonce unspent)
    Validate {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },

    /// Prepare notes to send to a third party as a payment
    Spend {
        #[clap(value_parser = parse_fedimint_amount)]
        amount: Amount,
    },

    /// Withdraw funds from the federation
    PegOut {
        address: Address,
        #[clap(value_parser = parse_bitcoin_amount)]
        satoshis: bitcoin::Amount,
    },

    /// Pay a lightning invoice via a gateway
    LnPay { bolt11: lightning_invoice::Invoice },

    /// Fetch (re-)issued notes and finalize issuance process
    Fetch,

    /// Display wallet info (holdings, tiers)
    Info,

    /// Create a lightning invoice to receive payment via gateway
    LnInvoice {
        #[clap(value_parser = parse_fedimint_amount)]
        amount: Amount,
        description: String,
        expiry_time: Option<u64>,
    },

    /// Wait for incoming invoice to be paid
    WaitInvoice { invoice: lightning_invoice::Invoice },

    /// Wait for the fed to reach a consensus block height
    WaitBlockHeight { height: u64 },

    /// Config enabling client to establish websocket connection to federation
    ConnectInfo,

    /// Join a federation using it's ConnectInfo
    JoinFederation { connect: String },

    /// List registered gateways
    ListGateways,

    /// Switch active gateway
    SwitchGateway {
        /// node public key for a gateway
        #[clap(value_parser = parse_node_pub_key)]
        pubkey: secp256k1::PublicKey,
    },

    /// Upload the (encrypted) snapshot of mint notes to federation
    Backup,

    /// Restore the previously created backup of mint notes (with `backup`
    /// command)
    Restore {
        /// The amount of nonces to look ahead when scanning epoch history (per
        /// amount tier)
        ///
        /// Larger values might make the restore initialization slower and
        /// memory usage slightly higher, but help restore all mint
        /// notes in some rare situations.
        #[clap(long = "gap-limit", default_value = "100")]
        gap_limit: usize,
    },

    /// Wipe the notes data from the DB. Useful for testing backup & restore
    #[clap(hide = true)]
    WipeNotes,
}

trait ErrorHandler<T, E> {
    fn or_terminate(self, err: CliErrorKind, msg: &str) -> T;
    fn transform<F>(self, success: F, err: CliErrorKind, msg: &str) -> CliResult
    where
        F: Fn(T) -> CliOutput;
}

impl<T, E: Into<Box<dyn Error>>> ErrorHandler<T, E> for Result<T, E> {
    fn or_terminate(self, err: CliErrorKind, msg: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => {
                let cli_error = CliError::from(err, msg, Some(e.into()));
                eprintln!("{cli_error}");
                exit(1);
            }
        }
    }
    fn transform<F>(self, success: F, err: CliErrorKind, msg: &str) -> CliResult
    where
        F: Fn(T) -> CliOutput,
    {
        match self {
            Ok(v) => Ok(success(v)),
            Err(e) => Err(CliError::from(err, msg, Some(e.into()))),
        }
    }
}

type CliResult = Result<CliOutput, CliError>;

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    notes: TieredMulti<SpendableNote>,
    invoice: lightning_invoice::Invoice,
}

#[tokio::main]
async fn main() {
    TracingSetup::default().init().expect("tracing initializes");

    if let Ok(cli) = CliNoWorkdir::try_parse() {
        // Only commands that don't need the workdir can be used here
        //TODO: remove allow when there are more commands
        #[allow(irrefutable_let_patterns)]
        if let CommandNoWorkdir::VersionHash = cli.command {
            println!(
                "{}",
                CliOutput::VersionHash {
                    hash: env!("CODE_VERSION").to_string()
                }
            );
        };
    } else {
        let module_gens = ModuleGenRegistry::from(vec![
            DynModuleGen::from(WalletGen),
            DynModuleGen::from(MintGen),
            DynModuleGen::from(LightningGen),
        ]);

        let cli = Cli::parse();
        if let Command::JoinFederation { connect } = cli.command {
            let connect_obj: WsClientConnectInfo = WsClientConnectInfo::from_str(&connect)
                .map_err(Box::<dyn Error>::from)
                .or_terminate(CliErrorKind::InvalidValue, "invalid connect info");
            let api = Arc::new(WsFederationApi::from_urls(&connect_obj))
                as Arc<dyn IFederationApi + Send + Sync + 'static>;
            let cfg: ClientConfig = api
                .download_client_config(&connect_obj.id, module_gens.clone())
                .await
                .or_terminate(
                    CliErrorKind::NetworkError,
                    "couldn't download config from peer",
                );
            let cfg_path = cli.workdir.join("client.json");
            std::fs::create_dir_all(&cli.workdir)
                .or_terminate(CliErrorKind::IOError, "failed to create config directory");
            let writer = std::fs::File::create(cfg_path)
                .or_terminate(CliErrorKind::IOError, "couldn't create config.json");
            serde_json::to_writer_pretty(writer, &cfg)
                .or_terminate(CliErrorKind::IOError, "couldn't write config");
            println!(
                "{}",
                &CliOutput::JoinFederation { joined: (connect) }.to_string()
            );
            return;
        };

        let cfg_path = cli.workdir.join("client.json");
        let db_path = cli.workdir.join("client.db");
        let cfg: UserClientConfig = load_from_file(&cfg_path).expect("Failed to parse config");
        let db = fedimint_rocksdb::RocksDb::open(db_path)
            .or_terminate(CliErrorKind::IOError, "could not open transaction db");
        let db = Database::new(db, module_decode_stubs());

        let rng = rand::rngs::OsRng;

        let decoders = ModuleDecoderRegistry::from_iter([
            (LEGACY_HARDCODED_INSTANCE_ID_LN, LightningDecoder.into()),
            (LEGACY_HARDCODED_INSTANCE_ID_MINT, MintDecoder.into()),
            (LEGACY_HARDCODED_INSTANCE_ID_WALLET, WalletDecoder.into()),
        ]);

        let client = Client::new(cfg.clone(), decoders, module_gens, db, Default::default()).await;

        let cli_result = handle_command(cli, client, rng).await;

        match cli_result {
            Ok(output) => {
                println!("{output}");
            }
            Err(err) => {
                eprintln!("{err}");
                exit(1);
            }
        }
    }
}

async fn handle_command(
    cli: Cli,
    client: Client<UserClientConfig>,
    mut rng: rand::rngs::OsRng,
) -> CliResult {
    let mut task_group = TaskGroup::new();
    match cli.command {
        Command::Api { method, arg } => {
            let arg: Value = serde_json::from_str(&arg).unwrap();
            let ws_api: Arc<_> = WsFederationApi::from_config(client.config().as_ref()).into();
            let response: Value = ws_api
                .request_with_strategy(
                    EventuallyConsistent::new(ws_api.peers().len()),
                    method,
                    vec![arg],
                )
                .await
                .unwrap();

            Ok(CliOutput::UntypedApiOutput { value: response })
        }
        Command::VersionHash => Ok(CliOutput::VersionHash {
            hash: env!("CODE_VERSION").to_string(),
        }),
        Command::PegInAddress => {
            let peg_in_address = client.get_new_pegin_address(rng).await;
            Ok(CliOutput::PegInAddress {
                address: (peg_in_address),
            })
        }
        Command::PegIn {
            txout_proof,
            transaction,
        } => client
            .peg_in(txout_proof, transaction, &mut rng)
            .await
            .transform(
                |v| CliOutput::PegIn { id: (v) },
                CliErrorKind::GeneralFederationError,
                "peg-in failed (no further information)",
            ),

        Command::Reissue { notes } => {
            let id = client.reissue(notes, &mut rng).await;
            id.transform(
                |v| CliOutput::Reissue { id: (v) },
                CliErrorKind::GeneralFederationError,
                "could not reissue notes (no further information)",
            )
        }
        Command::Validate { notes } => {
            let validate_result = client.validate_note_signatures(&notes).await;
            let details_vec = notes
                .iter()
                .map(|(amount, notes)| (amount.to_owned(), notes.len()))
                .collect();

            match validate_result {
                Ok(()) => Ok(CliOutput::Validate {
                    all_valid: true,
                    details: (details_vec),
                }),
                Err(_) => Ok(CliOutput::Validate {
                    all_valid: false,
                    details: (details_vec),
                }),
            }
        }
        Command::Spend { amount } => client.spend_ecash(amount, rng).await.transform(
            |v| CliOutput::Spend {
                note: (serialize_ecash(&v)),
            },
            CliErrorKind::GeneralFederationError,
            "failed to execute spend (no further information)",
        ),
        Command::Fetch => match client.fetch_all_notes().await {
            Ok(result) => Ok(CliOutput::Fetch { issuance: (result) }),
            Err(error) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed to fetch notes",
                Some(Box::new(error)),
            )),
        },
        Command::Info => {
            let notes = client.notes().await;
            let details_vec = notes
                .iter()
                .map(|(amount, notes)| (amount.to_owned(), notes.len()))
                .collect();
            Ok(CliOutput::Info {
                federation_id: client.config().as_ref().federation_id.to_string(),
                federation_name: client.config().as_ref().federation_name.clone(),
                network: client.wallet_client().config.network,
                total_amount: (notes.total_amount()),
                total_num_notes: (notes.count_items()),
                details: (details_vec),
            })
        }
        Command::PegOut { address, satoshis } => {
            match client.new_peg_out_with_fees(satoshis, address).await {
                Ok(peg_out) => match client.peg_out(peg_out, &mut rng).await {
                    Ok(out_point) => client
                        .wallet_client()
                        .await_peg_out_outcome(out_point)
                        .await
                        .transform(
                            |txid| CliOutput::PegOut { tx_id: (txid) },
                            CliErrorKind::GeneralFederationError,
                            "invalid peg-out outcome",
                        ),
                    Err(e) => Err(CliError::from(
                        CliErrorKind::GeneralFederationError,
                        "failed to commit peg-out",
                        Some(Box::new(e)),
                    )),
                },
                Err(e) => Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed to request peg-out",
                    Some(Box::new(e)),
                )),
            }
        }
        Command::LnPay { bolt11 } => {
            match client.fund_outgoing_ln_contract(bolt11, &mut rng).await {
                Ok((contract_id, outpoint)) => {
                    match client.await_outgoing_contract_acceptance(outpoint).await {
                        Ok(_) => client
                            .await_outgoing_contract_execution(contract_id, &mut rng)
                            .await
                            .transform(
                                |_| CliOutput::LnPay {
                                    contract_id: (contract_id),
                                },
                                CliErrorKind::GeneralFederationError,
                                "gateway failed to execute contract",
                            ),
                        Err(e) => Err(CliError::from(
                            CliErrorKind::Timeout,
                            "contract wasn't accepted in time",
                            Some(Box::new(e)),
                        )),
                    }
                }
                Err(e) => Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "Failure creating outgoing LN contract",
                    Some(Box::new(e)),
                )),
            }
        }
        Command::LnInvoice {
            amount,
            description,
            expiry_time,
        } => client
            .generate_confirmed_invoice(amount, description, &mut rng, expiry_time)
            .await
            .transform(
                |confirmed_invoice| CliOutput::LnInvoice {
                    invoice: (confirmed_invoice.invoice),
                },
                CliErrorKind::GeneralFederationError,
                "couldn't create invoice",
            ),
        Command::WaitInvoice { invoice } => {
            let contract_id = (*invoice.payment_hash()).into();
            client
                .claim_incoming_contract(contract_id, &mut rng)
                .await
                .transform(
                    |outpoint| CliOutput::WaitInvoice {
                        paid_in_tx: (outpoint),
                    },
                    CliErrorKind::Timeout,
                    "invoice did not get paid in time",
                )
        }
        Command::WaitBlockHeight { height } => {
            client.await_consensus_block_height(height).await.transform(
                |_| CliOutput::WaitBlockHeight { reached: (height) },
                CliErrorKind::Timeout,
                "timeout reached",
            )
        }
        Command::ConnectInfo => {
            let info = WsClientConnectInfo::from_honest_peers(client.config().as_ref());
            Ok(CliOutput::ConnectInfo {
                connect_info: (info),
            })
        }
        Command::JoinFederation { .. } => {
            unreachable!()
        }
        Command::ListGateways {} => match client.fetch_registered_gateways().await {
            Ok(gateways) => {
                if !gateways.is_empty() {
                    let mut gateways_json = json!(&gateways);
                    match client.fetch_active_gateway().await {
                        Ok(active_gateway) => {
                            gateways_json
                                .as_array_mut()
                                .expect("gateways_json is not an array")
                                .iter_mut()
                                .for_each(|gateway| {
                                    if gateway["node_pub_key"] == json!(active_gateway.node_pub_key)
                                    {
                                        gateway["active"] = json!(true);
                                    } else {
                                        gateway["active"] = json!(false);
                                    }
                                });
                            Ok(CliOutput::ListGateways {
                                num_gateways: (gateways.len()),
                                gateways: (gateways_json),
                            })
                        }
                        Err(e) => Err(CliError::from(
                            CliErrorKind::GeneralFederationError,
                            "could not determine active gateway",
                            Some(Box::new(e)),
                        )),
                    }
                } else {
                    Err(CliError::from(
                        CliErrorKind::GeneralFederationError,
                        "no gateways found",
                        None,
                    ))
                }
            }
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed to fetch gateways",
                Some(Box::new(e)),
            )),
        },
        Command::SwitchGateway { pubkey } => {
            match client.switch_active_gateway(Some(pubkey)).await {
                Ok(gateway) => {
                    let mut gateway_json = json!(&gateway);
                    gateway_json["active"] = json!(true);
                    Ok(CliOutput::SwitchGateway {
                        new_gateway: (gateway_json),
                    })
                }
                Err(e) => Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed to switch active gateway",
                    Some(Box::new(e)),
                )),
            }
        }
        Command::Backup => match client.mint_client().back_up_ecash_to_federation().await {
            Ok(_) => Ok(CliOutput::Backup),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        Command::Restore { gap_limit } => match client
            .mint_client()
            .restore_ecash_from_federation(gap_limit, &mut task_group)
            .await
        {
            Ok(_) => Ok(CliOutput::Backup),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
        Command::WipeNotes => match client.mint_client().wipe_notes().await {
            Ok(_) => Ok(CliOutput::Backup),
            Err(e) => Err(CliError::from(
                CliErrorKind::GeneralFederationError,
                "failed",
                Some(e.into()),
            )),
        },
    }
}

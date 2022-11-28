use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::process::exit;

use bitcoin::{secp256k1, Address, Transaction};
use clap::{Parser, Subcommand};
use fedimint_api::config::ClientConfig;
use fedimint_api::{Amount, NumPeers, OutPoint, TieredMulti, TransactionId};
use fedimint_core::config::load_from_file;
use fedimint_core::modules::ln::contracts::ContractId;
use fedimint_core::modules::ln::ContractAccount;
use fedimint_core::modules::wallet::txoproof::TxOutProof;
use mint_client::api::{WsFederationApi, WsFederationConnect};
use mint_client::mint::SpendableNote;
use mint_client::query::CurrentConsensus;
use mint_client::utils::{
    from_hex, parse_bitcoin_amount, parse_coins, parse_fedimint_amount, parse_node_pub_key,
    serialize_coins,
};
use mint_client::{Client, UserClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing_subscriber::EnvFilter;

#[derive(Serialize)]
#[serde(rename_all(serialize = "snake_case"))]
#[serde(untagged)]
enum CliOutput {
    VersionHash {
        hash: String,
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
        token: String,
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
        connect_info: WsFederationConnect,
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

    FetchContract {
        contract: Box<ContractAccount>,
    },
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

    /// Issue tokens in exchange for a peg-in proof (not yet implemented, just creates notes)
    PegIn {
        #[clap(value_parser = from_hex::<TxOutProof>)]
        txout_proof: TxOutProof,
        #[clap(value_parser = from_hex::<Transaction>)]
        transaction: Transaction,
    },

    /// Reissue tokens received from a third party to avoid double spends
    Reissue {
        #[clap(value_parser = parse_coins)]
        coins: TieredMulti<SpendableNote>,
    },

    /// Validate tokens without claiming them (only checks if signatures valid, does not check if nonce unspent)
    Validate {
        #[clap(value_parser = parse_coins)]
        coins: TieredMulti<SpendableNote>,
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

    /// Fetches a LN contract from the federation
    FetchContract { contract_id: ContractId },
}

trait ErrorHandler<T, E> {
    fn or_terminate(self, err: CliErrorKind, msg: &str) -> T;
    fn transform<F>(self, success: F, err: CliErrorKind, msg: &str) -> CliResult
    where
        F: Fn(T) -> CliOutput;
}

impl<T, E: Error + 'static> ErrorHandler<T, E> for Result<T, E> {
    fn or_terminate(self, err: CliErrorKind, msg: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => {
                let cli_error = CliError::from(err, msg, Some(Box::new(e)));
                println!("{}", cli_error);
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
            Err(e) => Err(CliError::from(err, msg, Some(Box::new(e)))),
        }
    }
}

type CliResult = Result<CliOutput, CliError>;

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    coins: TieredMulti<SpendableNote>,
    invoice: lightning_invoice::Invoice,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("error,mint_client=info,fedimint_cli=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Ok(cli) = CliNoWorkdir::try_parse() {
        // Only commands that don't need the workdir can be used here
        //TODO: remove allow when there are more commands
        #[allow(irrefutable_let_patterns)]
        if let CommandNoWorkdir::VersionHash = cli.command {
            println!(
                "{}",
                CliOutput::VersionHash {
                    hash: env!("GIT_HASH").to_string()
                }
            );
        };
    } else {
        let cli = Cli::parse();
        if let Command::JoinFederation { connect } = cli.command {
            let connect_obj: WsFederationConnect = serde_json::from_str(&connect)
                .or_terminate(CliErrorKind::InvalidValue, "invalid connect info");
            let api = WsFederationApi::new(connect_obj.members);
            let cfg: ClientConfig = api
                .request(
                    "/config",
                    (),
                    CurrentConsensus::new(api.peers().one_honest()),
                )
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
            .or_terminate(CliErrorKind::IOError, "could not open transaction db")
            .into();

        let rng = rand::rngs::OsRng;

        let client = Client::new(cfg.clone(), db, Default::default()).await;

        let cli_result = handle_command(cli, client, rng).await;

        match cli_result {
            Ok(output) => {
                println!("{}", output);
            }
            Err(err) => {
                println!("{}", err);
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
    match cli.command {
        Command::VersionHash => Ok(CliOutput::VersionHash {
            hash: env!("GIT_HASH").to_string(),
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

        Command::Reissue { coins } => {
            let id = client.reissue(coins, &mut rng).await;
            id.transform(
                |v| CliOutput::Reissue { id: (v) },
                CliErrorKind::GeneralFederationError,
                "could not reissue notes (no further information)",
            )
        }
        Command::Validate { coins } => {
            let validate_result = client.validate_note_signatures(&coins).await;
            let details_vec = coins
                .iter_tiers()
                .map(|(amount, coins)| (amount.to_owned(), coins.len()))
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
                token: (serialize_coins(&v)),
            },
            CliErrorKind::GeneralFederationError,
            "failed to execute spend (no further information)",
        ),
        Command::Fetch => {
            let mut result = Vec::<OutPoint>::new();
            let mut has_error = false;
            for fetch_result in client.fetch_all_coins().await {
                match fetch_result {
                    Ok(v) => result.push(v),
                    Err(_) => {
                        has_error = true;
                    }
                }
            }
            if has_error {
                Err(CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed to fetch notes",
                    None,
                ))
            } else {
                Ok(CliOutput::Fetch { issuance: (result) })
            }
        }
        Command::Info => {
            let coins = client.coins();
            let details_vec = coins
                .iter_tiers()
                .map(|(amount, coins)| (amount.to_owned(), coins.len()))
                .collect();
            Ok(CliOutput::Info {
                total_amount: (coins.total_amount()),
                total_num_notes: (coins.item_count()),
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
            .generate_invoice(amount, description, &mut rng, expiry_time)
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
            let info = WsFederationConnect::from(client.config().as_ref());
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
        Command::FetchContract { contract_id } => client
            .api_client()
            .fetch_contract(contract_id)
            .await
            .map(|contract| CliOutput::FetchContract {
                contract: Box::new(contract),
            })
            .map_err(|e| {
                CliError::from(
                    CliErrorKind::GeneralFederationError,
                    "failed to fetch contract",
                    Some(Box::new(e)),
                )
            }),
    }
}

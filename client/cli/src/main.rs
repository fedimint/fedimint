use bitcoin::{secp256k1, Address, Transaction};
use clap::Parser;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_core::config::{load_from_file, ClientConfig};
use fedimint_core::modules::ln::contracts::ContractId;
use fedimint_core::modules::mint::tiered::TieredMulti;
use fedimint_core::modules::wallet::txoproof::TxOutProof;

use core::fmt;
use mint_client::api::{WsFederationApi, WsFederationConnect};
use mint_client::mint::SpendableNote;
use mint_client::utils::{
    from_hex, parse_bitcoin_amount, parse_coins, parse_fedimint_amount, parse_node_pub_key,
    serialize_coins,
};
use mint_client::{Client, UserClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::process::exit;
use tracing_subscriber::EnvFilter;

#[derive(Serialize)]
#[serde(tag = "command")]
enum CliOutput {
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
        details: Vec<(SpendableNote, bool)>,
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
        total_num_coins: usize,
        details: Vec<(Amount, usize)>,
    },

    LnInvoice {
        invoice: String,
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
#[serde(tag = "error")]
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
        return write!(f, "{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

impl Error for CliError {}

#[derive(Parser)]
struct Options {
    workdir: PathBuf,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Generate a new peg-in address, funds sent to it can later be claimed
    PegInAddress,

    /// Issue tokens in exchange for a peg-in proof (not yet implemented, just creates coins)
    PegIn {
        #[clap(parse(try_from_str = from_hex))]
        txout_proof: TxOutProof,
        #[clap(parse(try_from_str = from_hex))]
        transaction: Transaction,
    },

    /// Reissue tokens received from a third party to avoid double spends
    Reissue {
        #[clap(parse(from_str = parse_coins))]
        coins: TieredMulti<SpendableNote>,
    },

    /// Validate tokens without claiming them (only checks if signatures valid, does not check if nonce unspent)
    Validate {
        #[clap(parse(from_str = parse_coins))]
        coins: TieredMulti<SpendableNote>,
    },

    /// Prepare coins to send to a third party as a payment
    Spend {
        #[clap(parse(try_from_str = parse_fedimint_amount))]
        amount: Amount,
    },

    /// Withdraw funds from the federation
    PegOut {
        address: Address,
        #[clap(parse(try_from_str = parse_bitcoin_amount))]
        satoshis: bitcoin::Amount,
    },

    /// Pay a lightning invoice via a gateway
    LnPay { bolt11: lightning_invoice::Invoice },

    /// Fetch (re-)issued coins and finalize issuance process
    Fetch,

    /// Display wallet info (holdings, tiers)
    Info,

    /// Create a lightning invoice to receive payment via gateway
    LnInvoice {
        #[clap(parse(try_from_str = parse_fedimint_amount))]
        amount: Amount,
        description: String,
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
        #[clap(parse(try_from_str = parse_node_pub_key))]
        pubkey: secp256k1::PublicKey,
    },
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
    invoice: String,
}

#[tokio::main]
async fn main() {
    let opts = Options::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Command::JoinFederation { connect } = opts.command {
        let connect_obj: WsFederationConnect = serde_json::from_str(&connect)
            .or_terminate(CliErrorKind::InvalidValue, "invalid connect info");
        let api = WsFederationApi::new(connect_obj.max_evil, connect_obj.members);
        let cfg: ClientConfig = api.request("/config", ()).await.or_terminate(
            CliErrorKind::NetworkError,
            "couldn't download config from peer",
        );
        let cfg_path = opts.workdir.join("client.json");
        std::fs::create_dir_all(&opts.workdir)
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

    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: UserClientConfig = load_from_file(&cfg_path);
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_default(&db_path)
            .or_terminate(CliErrorKind::IOError, "could not open transaction db");

    let rng = rand::rngs::OsRng::new().or_terminate(
        CliErrorKind::OSError,
        "failed to acquire random number generator from OS",
    );

    let client = Client::new(cfg.clone(), Box::new(db), Default::default());

    let cli_result = handle_command(opts, client, rng).await;

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

async fn handle_command(
    opts: Options,
    client: Client<UserClientConfig>,
    mut rng: rand::rngs::OsRng,
) -> CliResult {
    match opts.command {
        Command::PegInAddress => {
            let peg_in_address = client.get_new_pegin_address(&mut rng);
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
            let validate_result = client.validate_tokens(&coins).await;

            match validate_result {
                Ok(()) => Ok(CliOutput::Validate {
                    all_valid: (true),
                    details: ([].to_vec()),
                }),
                Err(_) => Ok(CliOutput::Validate {
                    all_valid: (false),
                    details: ([].to_vec()),
                }),
            }
        }
        Command::Spend { amount } => client.select_and_spend_coins(amount).transform(
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
                total_num_coins: (coins.item_count()),
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
                            .await_outgoing_contract_execution(contract_id)
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
                    CliErrorKind::InsufficientBalance,
                    "not enough coins",
                    Some(Box::new(e)),
                )),
            }
        }
        Command::LnInvoice {
            amount,
            description,
        } => client
            .generate_invoice(amount, description, &mut rng)
            .await
            .transform(
                |confirmed_invoice| CliOutput::LnInvoice {
                    invoice: (confirmed_invoice.invoice.to_string()),
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
                    "invoice did not appear in time",
                )
        }
        Command::WaitBlockHeight { height } => {
            client.await_consensus_block_height(height).await;
            Ok(CliOutput::WaitBlockHeight { reached: (height) })
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
    }
}

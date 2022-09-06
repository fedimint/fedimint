use bitcoin::{secp256k1, Address, Transaction};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use fedimint_api::Amount;
use fedimint_core::config::{load_from_file, ClientConfig};
use fedimint_core::modules::mint::tiered::TieredMulti;
use fedimint_core::modules::wallet::txoproof::TxOutProof;

use mint_client::api::{WsFederationApi, WsFederationConnect};
use mint_client::mint::SpendableNote;
use mint_client::utils::{
    from_hex, parse_bitcoin_amount, parse_coins, parse_fedimint_amount, parse_node_pub_key,
    serialize_coins,
};
use mint_client::{Client, UserClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
        let connect: WsFederationConnect =
            serde_json::from_str(&connect).expect("Invalid connect info");
        let api = WsFederationApi::new(connect.max_evil, connect.members);
        let cfg: ClientConfig = api
            .request("/config", ())
            .await
            .expect("Couldn't download config from peer");
        let cfg_path = opts.workdir.join("client.json");
        std::fs::create_dir_all(&opts.workdir).expect("Failed to create config directory");
        let writer = std::fs::File::create(cfg_path).expect("Couldn't create config.json");
        serde_json::to_writer_pretty(writer, &cfg).expect("couldn't write config");
        return;
    };

    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: UserClientConfig = load_from_file(&cfg_path);
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_default(&db_path).unwrap();

    let mut rng = rand::rngs::OsRng::new().unwrap();

    let client = Client::new(cfg.clone(), Box::new(db), Default::default());

    match opts.command {
        Command::PegInAddress => {
            println!("{}", client.get_new_pegin_address(&mut rng))
        }
        Command::PegIn {
            txout_proof,
            transaction,
        } => {
            let id = client
                .peg_in(txout_proof, transaction, &mut rng)
                .await
                .unwrap();
            info!(
                id = %id.to_hex(),
                "Started peg-in, please fetch the result later",
            );
        }
        Command::Reissue { coins } => {
            info!(coins = %coins.total_amount(), "Starting reissuance transaction");
            let id = client.reissue(coins, &mut rng).await.unwrap();
            info!(%id, "Started reissuance, please fetch the result later");
        }
        Command::Validate { coins } => {
            let validate_result = client.validate_tokens(&coins).await;

            match validate_result {
                Ok(()) => {
                    println!("All tokens have valid signatures");
                }
                Err(e) => {
                    println!("Found invalid token: {:?}", e);
                    std::process::exit(-1);
                }
            }
        }
        Command::Spend { amount } => {
            match client.select_and_spend_coins(amount) {
                Ok(outgoing_coins) => {
                    println!("{}", serialize_coins(&outgoing_coins));
                }
                Err(e) => {
                    error!(error = ?e);
                }
            };
        }
        Command::Fetch => {
            for fetch_result in client.fetch_all_coins().await {
                info!(issuance = %fetch_result.unwrap().txid.to_hex(), "Fetched coins");
            }
        }
        Command::Info => {
            let coins = client.coins();
            println!(
                "We own {} coins with a total value of {}",
                coins.item_count(),
                coins.total_amount()
            );
            for (amount, coins) in coins.iter_tiers() {
                println!("We own {} coins of denomination {}", coins.len(), amount);
            }
        }
        Command::PegOut { address, satoshis } => {
            let peg_out = client
                .new_peg_out_with_fees(satoshis, address)
                .await
                .unwrap();
            let out_point = client.peg_out(peg_out, &mut rng).await.unwrap();
            let txid = client
                .wallet_client()
                .await_peg_out_outcome(out_point)
                .await
                .unwrap();
            println!("Bitcoin transaction is about to be sent: {}", txid)
        }
        Command::LnPay { bolt11 } => {
            let (contract_id, outpoint) = client
                .fund_outgoing_ln_contract(bolt11, &mut rng)
                .await
                .expect("Not enough coins");

            client
                .await_outgoing_contract_acceptance(outpoint)
                .await
                .expect("Contract wasn't accepted in time");

            info!(
                %contract_id,
                "Funded outgoing contract, notifying gateway",
            );

            client
                .await_outgoing_contract_execution(contract_id)
                .await
                .expect("Gateway failed to execute contract");
        }
        Command::LnInvoice {
            amount,
            description,
        } => {
            let confirmed_invoice = client
                .generate_invoice(amount, description, &mut rng)
                .await
                .expect("Couldn't create invoice");
            println!("{}", confirmed_invoice.invoice)
        }
        Command::WaitInvoice { invoice } => {
            let contract_id = (*invoice.payment_hash()).into();
            let outpoint = client
                .claim_incoming_contract(contract_id, &mut rng)
                .await
                .expect("Timeout waiting for invoice payment");
            println!(
                "Paid in fedimint transaction {}. Call 'fetch' to get your coins.",
                outpoint.txid
            );
        }
        Command::WaitBlockHeight { height } => {
            client.await_consensus_block_height(height).await;
        }
        Command::ConnectInfo => {
            let info = WsFederationConnect::from(client.config().as_ref());
            println!("{}", serde_json::to_string(&info).unwrap());
        }
        Command::JoinFederation { .. } => {
            unreachable!()
        }
        Command::ListGateways {} => {
            println!("Fetching gateways from federation...");
            let gateways = client
                .fetch_registered_gateways()
                .await
                .expect("Failed to fetch gateways");
            println!("Found {} registered gateways : ", gateways.len());
            if !gateways.is_empty() {
                let mut gateways_json = json!(&gateways);
                if let Ok(active_gateway) = client.fetch_active_gateway().await {
                    gateways_json
                        .as_array_mut()
                        .expect("gateways_json is not an array")
                        .iter_mut()
                        .for_each(|gateway| {
                            if gateway["node_pub_key"] == json!(active_gateway.node_pub_key) {
                                gateway["active"] = json!(true);
                            } else {
                                gateway["active"] = json!(false);
                            }
                        });
                };
                println!(
                    "{}",
                    to_string_pretty(&gateways_json).expect("failed to deserialize gateways")
                );
            }
        }
        Command::SwitchGateway { pubkey } => {
            let gateway = client
                .switch_active_gateway(Some(pubkey))
                .await
                .expect("Failed to switch active gateway");
            println!("Successfully switched to gateway with the following details");
            let mut gateway_json = json!(&gateway);
            gateway_json["active"] = json!(true);
            println!(
                "{}",
                serde_json::to_string_pretty(&gateway_json)
                    .expect("Failed to deserialize activated gateway")
            );
        }
    }
}

use bitcoin::{Address, Transaction};
use bitcoin_hashes::hex::ToHex;
use clap::Parser;
use minimint_api::Amount;
use minimint_core::config::load_from_file;
use minimint_core::modules::ln::LightningGateway;
use minimint_core::modules::mint::tiered::coins::Coins;
use minimint_core::modules::wallet::txoproof::TxOutProof;

use mint_client::mint::SpendableCoin;
use mint_client::utils::{
    from_hex, parse_bitcoin_amount, parse_coins, parse_minimint_amount, serialize_coins,
};
use mint_client::{Client, GatewaySelection, UserClientConfig};
use serde::{Deserialize, Serialize};
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
        coins: Coins<SpendableCoin>,
    },

    /// Prepare coins to send to a third party as a payment
    Spend {
        #[clap(parse(try_from_str = parse_minimint_amount))]
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
        #[clap(parse(try_from_str = parse_minimint_amount))]
        amount: Amount,
        description: String,
    },

    /// Wait for incoming invoice to be paid
    WaitInvoice { invoice: lightning_invoice::Invoice },

    /// Wait for the fed to reach a consensus block height
    WaitBlockHeight { height: u64 },

    /// List gateways
    Gateways { active: bool },
}

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    coins: Coins<SpendableCoin>,
    invoice: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let opts = Options::parse();
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
            info!(coins = %coins.amount(), "Starting reissuance transaction");
            let id = client.reissue(coins, &mut rng).await.unwrap();
            info!(%id, "Started reissuance, please fetch the result later");
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
                coins.coin_count(),
                coins.amount()
            );
            for (amount, coins) in coins.coins {
                println!("We own {} coins of denomination {}", coins.len(), amount);
            }
        }
        Command::PegOut { address, satoshis } => {
            let peg_out = client
                .new_peg_out_with_fees(satoshis, address)
                .await
                .unwrap();
            client.peg_out(peg_out, &mut rng).await.unwrap();
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
                "Paid in minimint transaction {}. Call 'fetch' to get your coins.",
                outpoint.txid
            );
        }
        Command::WaitBlockHeight { height } => {
            client.await_consensus_block_height(height).await;
        }
        Command::Gateways { active } => {
            let gateways: Vec<LightningGateway>;

            if active {
                // List any gateways saved in the client database.
                gateways = client
                    .select_gateways(GatewaySelection::Active)
                    .await
                    .expect("Failed to fetch gateways");

                println!("Found {} active gateways : ", gateways.len());
            } else {
                // List any gateways registered with the federation.
                gateways = client
                    .select_gateways(GatewaySelection::Registered)
                    .await
                    .expect("Failed to fetch gateways");
                println!("Found {} registered gateways : ", gateways.len());
            }

            for (i, gateway) in gateways.iter().enumerate() {
                println!(
                    "{}: mint_pub_key: {}, node_pub_key: {}",
                    i, gateway.mint_pub_key, gateway.node_pub_key
                );
            }
        }
    }
}

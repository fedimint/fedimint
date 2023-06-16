use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use clap::{Args, Parser, Subcommand};
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::db::notifications::Notifications;
use fedimint_core::db::{DatabaseTransaction, SingleUseDatabaseTransaction};
use fedimint_core::module::DynServerModuleGen;
use fedimint_ln_server::common::db::{ContractKeyPrefix, ContractUpdateKeyPrefix, OfferKeyPrefix};
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::MintGen;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::config::io::read_server_config;
use fedimint_wallet_server::WalletGen;
use futures::StreamExt;
use prometheus::{Encoder, Histogram, HistogramOpts, Registry, TextEncoder};
use tokio::sync::RwLock;
use tracing::debug;

#[derive(Debug, Clone, Parser)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    Monitor(MonitorArgs),
}

#[derive(Debug, Clone, Args)]
struct MonitorArgs {
    #[clap(long)]
    database: String,
    #[clap(long)]
    cfg_dir: PathBuf,
    #[arg(long, env = "FM_PASSWORD")]
    password: String,

    #[arg(long, default_value = "[::]:3000", help = "Address to bind/listen to")]
    bind: String,

    #[arg(long, default_value = "25", help = "Update interval in seconds")]
    update_interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;
    let cli = Cli::parse();

    match cli.commands {
        Commands::Monitor(args) => monitor(args).await?,
    }
    Ok(())
}

async fn monitor(args: MonitorArgs) -> anyhow::Result<()> {
    let bind_address = SocketAddr::from_str(&args.bind)?;

    let state = Arc::new(RwLock::new(State::default()));
    let daemon = tokio::spawn(run_update_metrics_loop(Arc::clone(&state), args.clone()));

    let app = Router::new()
        .route("/metrics", get(|state| get_metrics(state, args)))
        .with_state(state);

    axum::Server::bind(&bind_address)
        .serve(app.into_make_service())
        .await?;
    daemon.await??;

    Ok(())
}

async fn run_update_metrics_loop(
    state: Arc<RwLock<State>>,
    args: MonitorArgs,
) -> anyhow::Result<()> {
    let cfg = read_server_config(&args.password, args.cfg_dir)?;

    loop {
        let start = fedimint_core::time::now();
        let read_only = RocksDbReadOnly::open_read_only(args.database.clone())?;
        let single_use = SingleUseDatabaseTransaction::new(read_only);
        let notifications = Box::new(Notifications::new());

        let module_inits = ServerModuleGenRegistry::from(vec![
            DynServerModuleGen::from(WalletGen),
            DynServerModuleGen::from(MintGen),
            DynServerModuleGen::from(LightningGen),
        ]);

        let decoders = module_inits.decoders(cfg.iter_module_instances())?;
        let mut dbtx = DatabaseTransaction::new(Box::new(single_use), decoders, &notifications);
        let ln_module_id = cfg
            .consensus
            .modules
            .iter()
            .find_map(|(module_id, module_cfg)| {
                if module_cfg.kind == fedimint_ln_server::common::KIND {
                    Some(*module_id)
                } else {
                    None
                }
            })
            .context("Expected to find a lightning module")?;
        let mut ln_incoming_offer = 0;
        let mut ln_contract_outcome_incoming = 0;
        let mut ln_contract_outcome_outgoing = 0;
        let mut ln_output_outcome_offer = 0;
        let mut ln_output_outcome_cancel_outgoing_contract = 0;
        let mut ln_funded_contract_incoming = 0;
        let mut ln_funded_contract_outgoing_cancelled = 0;
        let mut ln_funded_contract_outgoing = 0;
        let mut ln_funded_contract_incoming_account_amounts_sats = Vec::new();
        let mut ln_funded_contract_outgoing_cancelled_account_amounts_sats = Vec::new();
        let mut ln_funded_contract_outgoing_account_amounts_sats = Vec::new();

        // Read metrics under OfferKeyPrefix
        {
            let mut isolated_dbtx = dbtx.with_module_prefix(ln_module_id);
            let mut items = isolated_dbtx.find_by_prefix(&OfferKeyPrefix).await;

            while let Some((_k, _v)) = items.next().await {
                ln_incoming_offer += 1;
            }
        }

        // Read metrics under ContractUpdateKeyPrefix
        {
            let mut isolated_dbtx = dbtx.with_module_prefix(ln_module_id);
            let mut items = isolated_dbtx.find_by_prefix(&ContractUpdateKeyPrefix).await;

            while let Some((_k, v)) = items.next().await {
                match v {
                fedimint_ln_server::common::LightningOutputOutcome::Contract { id: _, outcome } => {
                    match outcome {
                        fedimint_ln_server::common::contracts::ContractOutcome::Incoming(_) => {
                            ln_contract_outcome_incoming += 1;
                        }
                        fedimint_ln_server::common::contracts::ContractOutcome::Outgoing(_) => {
                            ln_contract_outcome_outgoing += 1;
                        }
                    }
                }
                fedimint_ln_server::common::LightningOutputOutcome::Offer { id: _ } => {
                    ln_output_outcome_offer += 1;
                }
                fedimint_ln_server::common::LightningOutputOutcome::CancelOutgoingContract {
                    id: _,
                } => {
                    ln_output_outcome_cancel_outgoing_contract += 1;
                }
            }
            }
        }

        // Read metrics under ContractKeyPrefix
        {
            let mut isolated_dbtx = dbtx.with_module_prefix(ln_module_id);
            let mut items = isolated_dbtx.find_by_prefix(&ContractKeyPrefix).await;

            while let Some((_k, v)) = items.next().await {
                match v.contract {
                    fedimint_ln_server::common::contracts::FundedContract::Incoming(_) => {
                        ln_funded_contract_incoming_account_amounts_sats.push(v.amount);
                        ln_funded_contract_incoming += 1;
                    }
                    fedimint_ln_server::common::contracts::FundedContract::Outgoing(o) => {
                        if o.cancelled {
                            ln_funded_contract_outgoing_cancelled_account_amounts_sats
                                .push(v.amount);
                            ln_funded_contract_outgoing_cancelled += 1;
                        } else {
                            ln_funded_contract_outgoing_account_amounts_sats.push(v.amount);
                            ln_funded_contract_outgoing += 1;
                        }
                    }
                }
            }
        }

        // Save metrics to state
        {
            let mut state = state.write().await;
            let metrics = &state.metrics;
            metrics.ln_incoming_offer.set(ln_incoming_offer);
            metrics
                .ln_contract_outcome_incoming
                .set(ln_contract_outcome_incoming);
            metrics
                .ln_contract_outcome_outgoing
                .set(ln_contract_outcome_outgoing);
            metrics.ln_output_outcome_offer.set(ln_output_outcome_offer);
            metrics
                .ln_funded_contract_incoming
                .set(ln_funded_contract_incoming);
            metrics
                .ln_output_outcome_cancel_outgoing_contract
                .set(ln_output_outcome_cancel_outgoing_contract);
            metrics
                .ln_funded_contract_outgoing_cancelled
                .set(ln_funded_contract_outgoing_cancelled);
            metrics
                .ln_funded_contract_outgoing
                .set(ln_funded_contract_outgoing);

            // FIXME: it seems there is no way to reset the histogram, so the counts will
            // always increase
            let local = metrics
                .ln_funded_contract_incoming_account_amounts_sats
                .local();
            for m in ln_funded_contract_incoming_account_amounts_sats {
                local.observe(m.msats as f64 / 1000.0)
            }

            let local = metrics
                .ln_funded_contract_outgoing_cancelled_account_amounts_sats
                .local();
            for m in ln_funded_contract_outgoing_cancelled_account_amounts_sats {
                local.observe(m.msats as f64 / 1000.0)
            }

            let local = metrics
                .ln_funded_contract_outgoing_account_amounts_sats
                .local();
            for m in ln_funded_contract_outgoing_account_amounts_sats {
                local.observe(m.msats as f64 / 1000.0)
            }

            metrics
                .process_update_time_ms
                .set(start.elapsed()?.as_millis().try_into()?);
            state.last_update_time = Some(start);
        }
        let mut interval = Duration::from_secs(args.update_interval);
        interval = interval.saturating_sub(start.elapsed()?);
        debug!("Sleeping for {interval:?}");
        fedimint_core::task::sleep(interval).await;
    }
}

async fn get_metrics(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<State>>>,
    args: MonitorArgs,
) -> (StatusCode, String) {
    let state = state.read().await;
    if state.last_update_time.is_none()
        || fedimint_core::time::now()
            .duration_since(state.last_update_time.unwrap())
            .expect("time to work")
            > Duration::from_secs(args.update_interval) * 2
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Metrics are outdated, last updated time was: {:?}",
                state.last_update_time,
            ),
        );
    }
    let metric_families = state.metrics.registry.gather();
    let result = || -> anyhow::Result<String> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    };
    match result() {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
    }
}

#[derive(Default)]
struct State {
    metrics: PrometheusMetrics,
    last_update_time: Option<SystemTime>,
}

type U64IntGauge = prometheus::core::GenericGauge<prometheus::core::AtomicU64>;

#[derive(Debug, Clone)]
struct PrometheusMetrics {
    registry: Registry,
    ln_incoming_offer: U64IntGauge,
    ln_contract_outcome_incoming: U64IntGauge,
    ln_contract_outcome_outgoing: U64IntGauge,
    ln_output_outcome_offer: U64IntGauge,
    ln_output_outcome_cancel_outgoing_contract: U64IntGauge,
    ln_funded_contract_incoming: U64IntGauge,
    ln_funded_contract_outgoing: U64IntGauge,
    ln_funded_contract_outgoing_cancelled: U64IntGauge,
    ln_funded_contract_incoming_account_amounts_sats: Histogram,
    ln_funded_contract_outgoing_account_amounts_sats: Histogram,
    ln_funded_contract_outgoing_cancelled_account_amounts_sats: Histogram,
    process_update_time_ms: U64IntGauge,
}

impl PrometheusMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let ln_incoming_offer =
            U64IntGauge::new("ln_incoming_offer", "contracts::IncomingContractOffer")?;
        registry.register(Box::new(ln_incoming_offer.clone()))?;

        let ln_contract_outcome_incoming = U64IntGauge::new(
            "ln_contract_outcome_incoming",
            "contracts::ContractOutcome::Incoming",
        )?;
        registry.register(Box::new(ln_contract_outcome_incoming.clone()))?;

        let ln_contract_outcome_outgoing = U64IntGauge::new(
            "ln_contract_outcome_outgoing",
            "contracts::ContractOutcome::Outgoing",
        )?;
        registry.register(Box::new(ln_contract_outcome_outgoing.clone()))?;

        let ln_output_outcome_offer =
            U64IntGauge::new("ln_output_outcome_offer", "LightningOutputOutcome::Offer")?;
        registry.register(Box::new(ln_output_outcome_offer.clone()))?;

        let ln_output_outcome_cancel_outgoing_contract = U64IntGauge::new(
            "ln_output_outcome_cancel_outgoing_contract",
            "LightningOutputOutcome::CancelOutgoingContract",
        )?;
        registry.register(Box::new(ln_output_outcome_cancel_outgoing_contract.clone()))?;

        let ln_funded_contract_incoming = U64IntGauge::new(
            "ln_funded_contract_incoming",
            "contracts::FundedContract::Incoming",
        )?;
        registry.register(Box::new(ln_funded_contract_incoming.clone()))?;

        let ln_funded_contract_outgoing = U64IntGauge::new(
            "ln_funded_contract_outgoing",
            "contracts::FundedContract::Outgoing not cancelled",
        )?;
        registry.register(Box::new(ln_funded_contract_outgoing.clone()))?;

        let ln_funded_contract_outgoing_cancelled = U64IntGauge::new(
            "ln_funded_contract_outgoing_cancelled",
            "contracts::FundedContract::Outgoing cancelled",
        )?;
        registry.register(Box::new(ln_funded_contract_outgoing_cancelled.clone()))?;

        let amounts_buckets_sats = vec![0.0, 0.5, 1.0, 1000.0];
        let ln_funded_contract_incoming_account_amounts_sats = Histogram::with_opts(
            HistogramOpts::new(
                "ln_funded_contract_incoming_account_amounts_sats",
                "contracts::FundedContract::Incoming account amount in sats",
            )
            .buckets(amounts_buckets_sats.clone()),
        )?;
        registry.register(Box::new(
            ln_funded_contract_incoming_account_amounts_sats.clone(),
        ))?;

        let ln_funded_contract_outgoing_account_amounts_sats = Histogram::with_opts(
            HistogramOpts::new(
                "ln_funded_contract_outgoing_account_amounts_sats",
                "contracts::FundedContract::Outgoing not cancelled account amounts in sats",
            )
            .buckets(amounts_buckets_sats.clone()),
        )?;
        registry.register(Box::new(
            ln_funded_contract_outgoing_account_amounts_sats.clone(),
        ))?;

        let ln_funded_contract_outgoing_cancelled_account_amounts_sats = Histogram::with_opts(
            HistogramOpts::new(
                "ln_funded_contract_outgoing_cancelled_account_amounts_sats",
                "contracts::FundedContract::Outgoing cancelled account amounts in sats",
            )
            .buckets(amounts_buckets_sats),
        )?;
        registry.register(Box::new(
            ln_funded_contract_outgoing_cancelled_account_amounts_sats.clone(),
        ))?;

        let process_update_time_ms = U64IntGauge::new(
            "process_update_time_ms",
            "How much time it took to gather and update the metrics in milliseconds",
        )?;
        registry.register(Box::new(process_update_time_ms.clone()))?;

        Ok(Self {
            registry,
            ln_incoming_offer,
            ln_contract_outcome_incoming,
            ln_contract_outcome_outgoing,
            ln_output_outcome_offer,
            ln_output_outcome_cancel_outgoing_contract,
            ln_funded_contract_incoming,
            ln_funded_contract_outgoing,
            ln_funded_contract_outgoing_cancelled,
            ln_funded_contract_incoming_account_amounts_sats,
            ln_funded_contract_outgoing_account_amounts_sats,
            ln_funded_contract_outgoing_cancelled_account_amounts_sats,
            process_update_time_ms,
        })
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new().expect("to be able to initialize metrics")
    }
}

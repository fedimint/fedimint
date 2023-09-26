use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand, ValueEnum};
use common::{
    cln_create_invoice, cln_wait_invoice_payment, gateway_pay_invoice, get_note_summary,
    lnd_create_invoice, lnd_wait_invoice_payment, reissue_notes,
};
use devimint::cmd;
use devimint::util::{GatewayClnCli, GatewayLndCli};
use fedimint_client::Client;
use fedimint_core::api::{GlobalFederationApi, InviteCode, WsFederationApi};
use fedimint_core::endpoint_constants::FETCH_EPOCH_COUNT_ENDPOINT;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::spawn;
use fedimint_core::util::{BoxFuture, SafeUrl};
use fedimint_core::Amount;
use fedimint_mint_client::OOBNotes;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::common::{
    build_client, do_spend_notes, remint_denomination, switch_default_gateway, try_get_notes_cli,
};
pub mod common;

#[derive(Parser, Clone)]
#[command(version)]
struct Opts {
    #[arg(
        long,
        default_value = "10",
        help = "Number of users. Each user will work in parallel"
    )]
    users: u16,

    #[arg(long, help = "Output with the metrics results in JSON format")]
    metrics_json_output: Option<PathBuf>,

    #[arg(
        long,
        help = "If given, will be used to store and retrieve past metrics for comparison purposes"
    )]
    archive_dir: Option<PathBuf>,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LnInvoiceGeneration {
    ClnLightningCli,
    LnCli,
}

#[derive(Subcommand, Clone)]
enum Command {
    #[command(about = "Keep many websocket connections to a federation for a duration of time")]
    TestConnect {
        #[arg(long, help = "Federation invite code")]
        invite_code: String,
        #[arg(
            long,
            default_value = "60",
            help = "How much time to keep the connections open, in seconds"
        )]
        duration_secs: u64,
        #[arg(
            long,
            default_value = "120",
            help = "Timeout for connection attempt and for each request, in secnods"
        )]
        timeout_secs: u64,
        #[arg(
            long,
            help = "If given, will limit the number of endpoints (guardians) to connect to"
        )]
        limit_endpoints: Option<usize>,
    },
    #[command(about = "Try to download the client config many times.")]
    TestDownload {
        #[arg(long, help = "Federation invite code")]
        invite_code: String,
    },
    #[command(
        about = "Run a load test where many users in parallel will try to reissue notes and pay invoices through the gateway"
    )]
    LoadTest(LoadTestArgs),
}

#[derive(Args, Clone)]
struct LoadTestArgs {
    #[arg(
        long,
        help = "Federation invite code. If none given, we assume the client already has a config downloaded in DB"
    )]
    invite_code: Option<String>,

    #[arg(
        long,
        help = "Notes for the test. If none, will call fedimint-cli spend"
    )]
    initial_notes: Option<OOBNotes>,

    #[arg(
        long,
        help = "Gateway Id. If none, retrieve one according to --generate-invoice-with"
    )]
    gateway_id: Option<String>,

    #[arg(
        long,
        help = "The method used to generate invoices to be paid through the gateway. If none and no --invoices-file provided, no gateway/LN tests will be run. Note that you can't generate an invoice using the same lightning node used by the gateway (i.e self payment is forbidden)"
    )]
    generate_invoice_with: Option<LnInvoiceGeneration>,

    #[arg(
        long,
        default_value = "1",
        help = "How many invoices will be created for each user. Only applicable if --generate-invoice-with is provided"
    )]
    invoices_per_user: u16,

    #[arg(
        long,
        default_value = "0",
        help = "How many seconds to sleep between LN payments"
    )]
    ln_payment_sleep_secs: u64,

    #[arg(
        long,
        help = "A text file with one invoice per line. If --generate-invoice-with is provided, these will be additional invoices to be paid"
    )]
    invoices_file: Option<PathBuf>,

    #[arg(
        long,
        help = "How many notes to distribute to each user",
        default_value = "2"
    )]
    notes_per_user: u16,

    #[arg(
        long,
        help = "Note denomination to use for the test",
        default_value = "1024"
    )]
    note_denomination: Amount,

    #[arg(
        long,
        help = "Invoice amount when generating one",
        default_value = "1000"
    )]
    invoice_amount: Amount,
}

#[derive(Debug, Clone)]
pub struct MetricEvent {
    name: String,
    duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventMetricSummary {
    name: String,
    users: u64,
    n: u64,
    avg_ms: u128,
    median_ms: u128,
    max_ms: u128,
    min_ms: u128,
    timestamp_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct EventMetricComparison {
    avg_ms_gain: f64,
    median_ms_gain: f64,
    max_ms_gain: f64,
    min_ms_gain: f64,
    current: EventMetricSummary,
    previous: EventMetricSummary,
}

impl std::fmt::Display for EventMetricComparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn to_percent(gain: f64) -> String {
            if gain >= 1.0 {
                format!("+{:.2}%", (gain - 1.0) * 100.0)
            } else {
                format!("-{:.2}%", (1.0 - gain) * 100.0)
            }
        }
        f.write_str(&format!(
            "avg: {}, median: {}, max: {}, min: {}",
            to_percent(self.avg_ms_gain),
            to_percent(self.median_ms_gain),
            to_percent(self.max_ms_gain),
            to_percent(self.min_ms_gain),
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    let opts = Opts::parse();
    let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();
    let summary_handle = spawn("handle metrics summary", {
        let opts = opts.clone();
        async move { handle_metrics_summary(opts, event_receiver).await }
    })
    .expect("some handle on non-wasm");
    let futures = match opts.command.clone() {
        Command::TestConnect {
            invite_code,
            duration_secs,
            timeout_secs,
            limit_endpoints,
        } => {
            let invite_code = InviteCode::from_str(&invite_code).context("invalid invite code")?;
            test_connect_raw_client(
                invite_code,
                opts.users,
                Duration::from_secs(duration_secs),
                Duration::from_secs(timeout_secs),
                limit_endpoints,
                event_sender.clone(),
            )
            .await?
        }
        Command::TestDownload { invite_code } => {
            let invite_code = InviteCode::from_str(&invite_code).context("invalid invite code")?;
            test_download_config(invite_code, opts.users, event_sender.clone()).await?
        }
        Command::LoadTest(args) => {
            let invite_code = if let Some(invite_code) = args.invite_code {
                Some(InviteCode::from_str(&invite_code).context("invalid invite code")?)
            } else {
                None
            };

            let initial_notes = if let Some(initial_notes) = args.initial_notes {
                initial_notes
            } else {
                try_get_notes_cli(&Amount::from_sats(2000), 5).await?
            };

            let gateway_id = if let Some(gateway_id) = args.gateway_id {
                Some(gateway_id)
            } else if let Some(generate_invoice_with) = args.generate_invoice_with {
                Some(get_gateway_id(generate_invoice_with).await?)
            } else {
                None
            };
            let invoices = if let Some(invoices_file) = args.invoices_file {
                let invoices_file = tokio::fs::File::open(invoices_file).await?;
                let mut lines = tokio::io::BufReader::new(invoices_file).lines();
                let mut invoices = vec![];
                while let Some(line) = lines.next_line().await? {
                    let invoice = Bolt11Invoice::from_str(&line)?;
                    invoices.push(invoice);
                }
                invoices
            } else {
                vec![]
            };
            if args.generate_invoice_with.is_none() && invoices.is_empty() {
                info!("No --generate-invoice-with given no invoices on --invoices-file, not LN/gateway tests will be run")
            }
            run_load_test(
                opts.archive_dir,
                opts.users,
                invite_code,
                initial_notes,
                args.generate_invoice_with,
                args.invoices_per_user,
                Duration::from_secs(args.ln_payment_sleep_secs),
                invoices,
                gateway_id,
                args.notes_per_user,
                args.note_denomination,
                args.invoice_amount,
                event_sender.clone(),
            )
            .await?
        }
    };

    let result = futures::future::join_all(futures).await;
    drop(event_sender);
    summary_handle.await??;
    let len_failures = result.iter().filter(|r| r.is_err()).count();
    eprintln!("{} results, {len_failures} failures", result.len());
    for r in result {
        if let Err(e) = r {
            warn!("Task failed: {:?}", e);
        }
    }
    if len_failures > 0 {
        bail!("Finished with failures");
    } else {
        info!("Finished successfully")
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_load_test(
    archive_dir: Option<PathBuf>,
    users: u16,
    invite_code: Option<InviteCode>,
    initial_notes: OOBNotes,
    generate_invoice_with: Option<LnInvoiceGeneration>,
    generated_invoices_per_user: u16,
    ln_payment_sleep: Duration,
    invoices_from_file: Vec<Bolt11Invoice>,
    gateway_id: Option<String>,
    notes_per_user: u16,
    note_denomination: Amount,
    invoice_amount: Amount,
    event_sender: mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<Vec<BoxFuture<'static, anyhow::Result<()>>>> {
    let db_path = archive_dir.as_ref().map(|p| p.join("db"));
    let coordinator_db = if let Some(db_path) = &db_path {
        tokio::fs::create_dir_all(db_path).await?;
        Some(db_path.join("coordinator.db"))
    } else {
        None
    };
    let coordinator = build_client(invite_code.clone(), coordinator_db.as_ref()).await?;
    let mut users_clients = Vec::with_capacity(users.into());
    for u in 0..users {
        let user_db = db_path
            .as_ref()
            .map(|db_path| db_path.join(format!("user_{u}.db")));
        let client = build_client(invite_code.clone(), user_db.as_ref()).await?;
        if let Some(gateway_id) = &gateway_id {
            switch_default_gateway(&client, gateway_id).await?;
        }
        users_clients.push(client);
    }

    let amount = initial_notes.total_amount();

    info!("Reissuing initial notes: initial {amount}");
    reissue_notes(&coordinator, initial_notes, &event_sender).await?;

    info!("Reminting notes of denomination {note_denomination} for {users} users, {notes_per_user} notes per user (this may take a while if the number of users/notes is high)");
    let total_quantity_to_remint = notes_per_user * users;
    remint_denomination(&coordinator, note_denomination, total_quantity_to_remint).await?;

    info!("Note summary:");
    let summary = get_note_summary(&coordinator).await?;
    for (k, v) in summary.iter() {
        info!("{k}: {v}");
    }

    let mut users_notes = HashMap::new();
    for u in 0..users {
        users_notes.insert(u, Vec::with_capacity(notes_per_user.into()));
        for _ in 0..notes_per_user {
            let (_, oob_notes) = do_spend_notes(&coordinator, note_denomination).await?;
            let user_amount = oob_notes.total_amount();
            info!("Giving {user_amount} to user {u}");
            users_notes.get_mut(&u).unwrap().push(oob_notes);
        }
    }
    let mut users_invoices = HashMap::new();
    let mut user = 0;
    // Distribute invoices to users in a round robin fashion
    for invoice in invoices_from_file {
        users_invoices
            .entry(user)
            .or_insert_with(Vec::new)
            .push(invoice);
        user = (user + 1) % users;
    }

    info!("Starting user tasks");
    let futures = users_clients
        .into_iter()
        .enumerate()
        .map(|(u, client)| {
            let u = u as u16;
            let oob_notes = users_notes.remove(&u).unwrap();
            let invoices = users_invoices.remove(&u).unwrap_or_default();
            let event_sender = event_sender.clone();
            let f: BoxFuture<_> = Box::pin(do_user_task(
                client,
                oob_notes,
                generated_invoices_per_user,
                ln_payment_sleep,
                invoice_amount,
                invoices,
                generate_invoice_with,
                event_sender,
            ));
            f
        })
        .collect::<Vec<_>>();

    Ok(futures)
}

#[allow(clippy::too_many_arguments)]
async fn do_user_task(
    client: Client,
    oob_notes: Vec<OOBNotes>,
    generated_invoices_per_user: u16,
    ln_payment_sleep: Duration,
    invoice_amount: Amount,
    additional_invoices: Vec<Bolt11Invoice>,
    generate_invoice_with: Option<LnInvoiceGeneration>,
    event_sender: mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<()> {
    for oob_note in oob_notes {
        let amount = oob_note.total_amount();
        reissue_notes(&client, oob_note, &event_sender)
            .await
            .map_err(|e| anyhow::anyhow!("while reissuing initial {amount}: {e}"))?;
    }
    let mut generated_invoices_per_user_iterator = (0..generated_invoices_per_user).peekable();
    while let Some(_) = generated_invoices_per_user_iterator.next() {
        let total_amount = get_note_summary(&client).await?.total_amount();
        if invoice_amount > total_amount {
            warn!("Can't pay invoice, not enough funds: {invoice_amount} > {total_amount}");
        } else {
            match generate_invoice_with {
                Some(LnInvoiceGeneration::ClnLightningCli) => {
                    let (invoice, label) = cln_create_invoice(invoice_amount).await?;
                    gateway_pay_invoice(&client, invoice, &event_sender).await?;
                    cln_wait_invoice_payment(&label).await?;
                }
                Some(LnInvoiceGeneration::LnCli) => {
                    let (invoice, r_hash) = lnd_create_invoice(invoice_amount).await?;
                    gateway_pay_invoice(&client, invoice, &event_sender).await?;
                    lnd_wait_invoice_payment(r_hash).await?;
                }
                None if additional_invoices.is_empty() => {
                    debug!("No method given to generate an invoice and no invoices on file, will not test the gateway");
                    break;
                }
                None => {
                    break;
                }
            };
            if generated_invoices_per_user_iterator.peek().is_some() {
                // Only sleep while there are more invoices to pay
                fedimint_core::task::sleep(ln_payment_sleep).await;
            }
        }
    }
    let mut additional_invoices = additional_invoices.into_iter().peekable();
    while let Some(invoice) = additional_invoices.next() {
        let total_amount = get_note_summary(&client).await?.total_amount();
        let invoice_amount =
            Amount::from_msats(invoice.amount_milli_satoshis().unwrap_or_default());
        if invoice_amount > total_amount {
            warn!("Can't pay invoice, not enough funds: {invoice_amount} > {total_amount}");
        } else if invoice_amount == Amount::ZERO {
            warn!("Can't pay invoice {invoice}, amount is zero");
        } else {
            gateway_pay_invoice(&client, invoice, &event_sender).await?;
            if additional_invoices.peek().is_some() {
                // Only sleep while there are more invoices to pay
                fedimint_core::task::sleep(ln_payment_sleep).await;
            }
        }
    }
    Ok(())
}

async fn test_download_config(
    invite_code: InviteCode,
    users: u16,
    event_sender: mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<Vec<BoxFuture<'static, anyhow::Result<()>>>> {
    let api = Arc::new(WsFederationApi::from_invite_code(&[invite_code.clone()]));

    Ok((0..users)
        .map(|_| {
            let api = api.clone();
            let invite_code = invite_code.clone();
            let event_sender = event_sender.clone();
            let f: BoxFuture<_> = Box::pin(async move {
                let m = fedimint_core::time::now();
                let _ = api.download_client_config(&invite_code).await?;
                event_sender.send(MetricEvent {
                    name: "download_client_config".into(),
                    duration: m.elapsed()?,
                })?;
                Ok(())
            });
            f
        })
        .collect())
}

async fn test_connect_raw_client(
    invite_code: InviteCode,
    users: u16,
    duration: Duration,
    timeout: Duration,
    limit_endpoints: Option<usize>,
    event_sender: mpsc::UnboundedSender<MetricEvent>,
) -> anyhow::Result<Vec<BoxFuture<'static, anyhow::Result<()>>>> {
    let api = Arc::new(WsFederationApi::from_invite_code(&[invite_code.clone()]));
    let mut cfg = api.download_client_config(&invite_code).await?;

    if let Some(limit_endpoints) = limit_endpoints {
        cfg.global.api_endpoints = cfg
            .global
            .api_endpoints
            .into_iter()
            .take(limit_endpoints)
            .collect();
        info!("Limiting endpoints to {:?}", cfg.global.api_endpoints);
    }
    use jsonrpsee_core::client::ClientT;
    use jsonrpsee_ws_client::WsClientBuilder;

    info!("Connecting to {users} clients");
    let clients = (0..users)
        .flat_map(|_| {
            let clients = cfg.global.api_endpoints.values().map(|url| async {
                let ws_client = WsClientBuilder::default()
                    .use_webpki_rustls()
                    .request_timeout(timeout)
                    .connection_timeout(timeout)
                    .build(url_to_string_with_default_port(&url.url))
                    .await?;
                Ok::<_, anyhow::Error>(ws_client)
            });
            clients
        })
        .collect::<Vec<_>>();
    let clients = futures::future::try_join_all(clients).await?;
    info!("Keeping {users} clients connected for {duration:?}");
    Ok(clients
        .into_iter()
        .map(|client| {
            let event_sender = event_sender.clone();
            let f: BoxFuture<_> = Box::pin(async move {
                let initial_time = fedimint_core::time::now();
                while initial_time.elapsed()? < duration {
                    let m = fedimint_core::time::now();
                    let _epoch: u64 = client
                        .request::<_, _>(
                            FETCH_EPOCH_COUNT_ENDPOINT,
                            vec![ApiRequestErased::default()],
                        )
                        .await?;
                    event_sender.send(MetricEvent {
                        name: FETCH_EPOCH_COUNT_ENDPOINT.into(),
                        duration: m.elapsed()?,
                    })?;
                    fedimint_core::task::sleep(Duration::from_secs(1)).await;
                }
                Ok(())
            });
            f
        })
        .collect())
}

fn url_to_string_with_default_port(url: &SafeUrl) -> String {
    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host().expect("Asserted on construction"),
        url.port_or_known_default()
            .expect("Asserted on construction"),
        url.path()
    )
}

async fn handle_metrics_summary(
    opts: Opts,
    mut event_receiver: mpsc::UnboundedReceiver<MetricEvent>,
) -> anyhow::Result<()> {
    let timestamp_seconds = fedimint_core::time::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut metrics_json_output_files = vec![];
    let mut previous_metrics = vec![];
    let mut comparison_output = None;
    if let Some(archive_dir) = opts.archive_dir {
        let mut archive_metrics = archive_dir.join("metrics");
        archive_metrics.push(opts.users.to_string());
        tokio::fs::create_dir_all(&archive_metrics).await?;
        let mut archive_comparisons = archive_dir.join("comparisons");
        archive_comparisons.push(opts.users.to_string());
        tokio::fs::create_dir_all(&archive_comparisons).await?;

        let latest_metrics_file = std::fs::read_dir(&archive_metrics)?
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                let created = metadata
                    .created()
                    .unwrap_or_else(|_| metadata.modified().unwrap());
                (entry, created)
            })
            .max_by_key(|(_entry, created)| created.to_owned())
            .map(|(entry, _)| entry.path());
        if let Some(latest_metrics_file) = latest_metrics_file {
            let latest_metrics_file = tokio::fs::File::open(latest_metrics_file).await?;
            let mut lines = tokio::io::BufReader::new(latest_metrics_file).lines();
            while let Some(line) = lines.next_line().await? {
                match serde_json::from_str::<EventMetricSummary>(&line) {
                    Ok(metric) => {
                        previous_metrics.push(metric);
                    }
                    Err(e) => {
                        warn!("Failed to parse previous metric: {e:?}");
                    }
                }
            }
        }
        let new_metric_output = archive_metrics.join(format!("{timestamp_seconds}.json",));
        let new_metric_output = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(new_metric_output)
                .await?,
        );
        metrics_json_output_files.push(new_metric_output);
        if !previous_metrics.is_empty() {
            let new_comparison_output =
                archive_comparisons.join(format!("{timestamp_seconds}.json",));
            comparison_output = Some(BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(new_comparison_output)
                    .await?,
            ));
        }
    }
    if let Some(metrics_json_output) = opts.metrics_json_output {
        metrics_json_output_files.push(BufWriter::new(
            tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(metrics_json_output)
                .await?,
        ))
    }

    let mut results = HashMap::new();
    while let Some(event) = event_receiver.recv().await {
        let entry = results.entry(event.name).or_insert_with(Vec::new);
        entry.push(event.duration);
    }

    let mut previous_metrics = previous_metrics
        .into_iter()
        .map(|metric| (metric.name.clone(), metric))
        .collect::<HashMap<_, _>>();

    for (k, mut v) in results {
        v.sort();
        let n = v.len();
        let max = v.iter().last().unwrap();
        let min = v.first().unwrap();
        let median = v[n / 2];
        let sum: Duration = v.iter().sum();
        let avg = sum / n as u32;
        let metric_summary = EventMetricSummary {
            name: k.clone(),
            users: opts.users as u64,
            n: n as u64,
            avg_ms: avg.as_millis(),
            median_ms: median.as_millis(),
            max_ms: max.as_millis(),
            min_ms: min.as_millis(),
            timestamp_seconds,
        };
        let comparison = if let Some(previous_metric) = previous_metrics.remove(&k) {
            if previous_metric.n == metric_summary.n {
                fn calculate_gain(current: u128, previous: u128) -> f64 {
                    current as f64 / previous as f64
                }
                let comparison = EventMetricComparison {
                    avg_ms_gain: calculate_gain(metric_summary.avg_ms, previous_metric.avg_ms),
                    median_ms_gain: calculate_gain(
                        metric_summary.median_ms,
                        previous_metric.median_ms,
                    ),
                    max_ms_gain: calculate_gain(metric_summary.max_ms, previous_metric.max_ms),
                    min_ms_gain: calculate_gain(metric_summary.min_ms, previous_metric.min_ms),
                    current: metric_summary.clone(),
                    previous: previous_metric,
                };
                if let Some(comparison_output) = &mut comparison_output {
                    let comparison_json =
                        serde_json::to_string(&comparison).expect("to be serializable");
                    comparison_output
                        .write_all(format!("{comparison_json}\n").as_bytes())
                        .await
                        .expect("to write on file");
                }
                Some(comparison)
            } else {
                info!("Skipping comparison for {k} because previous metric has different n ({} vs {})", previous_metric.n, metric_summary.n);
                None
            }
        } else {
            None
        };
        if let Some(comparison) = comparison {
            println!("{n} {k}: avg {avg:?}, median {median:?}, max {max:?}, min {min:?} (compared to previous: {comparison})");
        } else {
            println!("{n} {k}: avg {avg:?}, median {median:?}, max {max:?}, min {min:?}");
        }
        let metric_summary_json =
            serde_json::to_string(&metric_summary).expect("to be serializable");
        for metrics_json_output_file in &mut metrics_json_output_files {
            metrics_json_output_file
                .write_all(format!("{metric_summary_json}\n").as_bytes())
                .await
                .expect("to write on file");
        }
    }
    for mut output in metrics_json_output_files {
        output.flush().await?;
    }
    if let Some(mut output) = comparison_output {
        output.flush().await?;
    }
    Ok(())
}

async fn get_gateway_id(generate_invoice_with: LnInvoiceGeneration) -> anyhow::Result<String> {
    let gateway_json = match generate_invoice_with {
        LnInvoiceGeneration::ClnLightningCli => {
            // If we are paying a lnd invoice, we use the cln gateway
            cmd!(GatewayLndCli, "info").out_json().await
        }
        LnInvoiceGeneration::LnCli => {
            // and vice-versa
            cmd!(GatewayClnCli, "info").out_json().await
        }
    }?;
    let gateway_id = gateway_json["gateway_id"]
        .as_str()
        .context("Missing gateway_id field")?;

    Ok(gateway_id.into())
}

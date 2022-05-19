use clap::Parser;
use minimint::config::{load_from_file, ServerConfig, ServerOpts};
use minimint::run_minimint;
use opentelemetry::global;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Install an otel pipeline with a simple span processor that exports data one at a time when
    // spans end. See the `install_batch` option on each exporter's pipeline builder to see how to
    // export in batches.
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name("minimint")
        .install_simple()
        .unwrap();

    let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(opentelemetry)
        .with(fmt_layer)
        .init();

    let opts = ServerOpts::parse();
    let cfg: ServerConfig = load_from_file(&opts.cfg_path);

    run_minimint(cfg).await;
    global::shutdown_tracer_provider();
}

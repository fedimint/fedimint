use std::fs::File;
use std::{env, io};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Constants for categorizing the logging type
pub const LOG_BLOCKCHAIN: &str = "net::blockchain";
pub const LOG_CONSENSUS: &str = "consensus";
pub const LOG_CORE: &str = "core";
pub const LOG_DB: &str = "db";
pub const LOG_DEVIMINT: &str = "devimint";
pub const LOG_ECASH_RECOVERY: &str = "ecash-recovery";
pub const LOG_NET_API: &str = "net::api";
pub const LOG_NET_PEER_DKG: &str = "net::peer::dkg";
pub const LOG_NET_PEER: &str = "net::peer";
pub const LOG_NET: &str = "net";
pub const LOG_TASK: &str = "task";
pub const LOG_TEST: &str = "test";
pub const LOG_TIMING: &str = "timing";
pub const LOG_WALLET: &str = "wallet";
pub const LOG_CLIENT: &str = "client";
pub const LOG_CLIENT_NET_API: &str = "client::net::api";
pub const LOG_CLIENT_BACKUP: &str = "client::backup";
pub const LOG_CLIENT_RECOVERY: &str = "client::recovery";
pub const LOG_CLIENT_RECOVERY_MINT: &str = "client::recovery::mint";

/// Consolidates the setup of server tracing into a helper
#[derive(Default)]
pub struct TracingSetup {
    #[cfg(feature = "telemetry")]
    tokio_console_bind: Option<std::net::SocketAddr>,
    #[cfg(feature = "telemetry")]
    with_jaeger: bool,
    #[cfg(feature = "telemetry")]
    with_chrome: bool,
    with_file: Option<File>,
}

impl TracingSetup {
    /// Setup a console server for tokio logging <https://docs.rs/console-subscriber>
    #[cfg(feature = "telemetry")]
    pub fn tokio_console_bind(&mut self, address: Option<std::net::SocketAddr>) -> &mut Self {
        self.tokio_console_bind = address;
        self
    }

    /// Setup telemetry through Jaeger <https://docs.rs/tracing-jaeger>
    #[cfg(feature = "telemetry")]
    pub fn with_jaeger(&mut self, enabled: bool) -> &mut Self {
        self.with_jaeger = enabled;
        self
    }

    /// Setup telemetry through Chrome <https://docs.rs/tracing-chrome>
    #[cfg(feature = "telemetry")]
    pub fn with_chrome(&mut self, enabled: bool) -> &mut Self {
        self.with_chrome = enabled;
        self
    }

    pub fn with_file(&mut self, file: Option<File>) -> &mut Self {
        self.with_file = file;
        self
    }

    /// Initialize the logging, must be called for tracing to begin
    pub fn init(&mut self) -> anyhow::Result<()> {
        use tracing_subscriber::fmt::writer::{BoxMakeWriter, Tee};

        let var = env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV).unwrap_or_default();
        let filter_layer = EnvFilter::builder().parse(format!(
            // We prefix everything with a default general log level and
            // good per-module specific default. User provided RUST_LOG
            // can override one or both
            "info,jsonrpsee_core::client::async_client=off,{}",
            var
        ))?;

        let fmt_writer = if let Some(file) = self.with_file.take() {
            BoxMakeWriter::new(Tee::new(io::stderr, file))
        } else {
            BoxMakeWriter::new(io::stderr)
        };

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_thread_names(false) // can be enabled for debugging
            .with_writer(fmt_writer)
            .with_filter(filter_layer);

        let console_opt = || -> Option<Box<dyn Layer<_> + Send + Sync + 'static>> {
            #[cfg(feature = "telemetry")]
            if let Some(l) = self.tokio_console_bind {
                let tracer = console_subscriber::ConsoleLayer::builder()
                    .retention(std::time::Duration::from_secs(60))
                    .server_addr(l)
                    .spawn()
                    // tokio-console cares only about these layers, so we filter separately for it
                    .with_filter(EnvFilter::new("tokio=trace,runtime=trace"));
                return Some(tracer.boxed());
            }
            None
        };

        let telemetry_layer_opt = || -> Option<Box<dyn Layer<_> + Send + Sync + 'static>> {
            #[cfg(feature = "telemetry")]
            if self.with_jaeger {
                let tracer = opentelemetry_jaeger::new_agent_pipeline()
                    .with_service_name("fedimint")
                    .install_simple()
                    .unwrap();

                return Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed());
            }
            None
        };

        let chrome_layer_opt = || -> Option<Box<dyn Layer<_> + Send + Sync + 'static>> {
            #[cfg(feature = "telemetry")]
            if self.with_chrome {
                let (cr_layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
                    .include_args(true)
                    .build();
                // drop guard cause file to written and closed
                // in this case file will closed after exit of program
                std::mem::forget(guard);

                return Some(cr_layer.boxed());
            }
            None
        };

        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(console_opt())
            .with(telemetry_layer_opt())
            .with(chrome_layer_opt())
            .try_init()?;
        Ok(())
    }
}

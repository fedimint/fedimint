use std::net::SocketAddr;
use std::time::Duration;

pub use fedimint_core::logging::*;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub const LOG_CONSENSUS: &str = "consensus";
pub const LOG_NET: &str = "net";
pub const LOG_NET_PEER: &str = "net::peer";
pub const LOG_NET_PEER_DKG: &str = "net::peer::dkg";
pub const LOG_DB: &str = "db";

/// Consolidates the setup of server tracing into a helper
#[derive(Default)]
pub struct TracingSetup {
    tokio_console_bind: Option<SocketAddr>,
    with_jaeger: bool,
    with_chrome: bool,
}

impl TracingSetup {
    /// Setup a console server for tokio logging https://docs.rs/console-subscriber
    pub fn tokio_console_bind(&mut self, address: Option<SocketAddr>) -> &mut Self {
        self.tokio_console_bind = address;
        self
    }

    /// Setup telemetry through Jaeger https://docs.rs/tracing-jaeger
    #[cfg(feature = "telemetry")]
    pub fn with_jaeger(&mut self, enabled: bool) -> &mut Self {
        self.with_jaeger = enabled;
        self
    }

    /// Setup telemetry through Chrome https://docs.rs/tracing-chrome
    #[cfg(feature = "telemetry")]
    pub fn with_chrome(&mut self, enabled: bool) -> &mut Self {
        self.with_chrome = enabled;
        self
    }

    /// Initialize the logging, must be called for tracing to begin
    pub fn init(&self) -> anyhow::Result<()> {
        let filter_layer =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let fmt_layer = tracing_subscriber::fmt::layer().with_filter(filter_layer);

        let console_opt = self.tokio_console_bind.map(|l| {
            console_subscriber::ConsoleLayer::builder()
                .retention(Duration::from_secs(60))
                .server_addr(l)
                .spawn()
                // tokio-console cares only about these layers, so we filter separately for it
                .with_filter(EnvFilter::new("tokio=trace,runtime=trace"))
        });

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
                let (cr_layer, gaurd) = tracing_chrome::ChromeLayerBuilder::new()
                    .include_args(true)
                    .build();
                // drop gaurd cause file to written and closed
                // in this case file will closed after exit of program
                std::mem::forget(gaurd);

                return Some(cr_layer.boxed());
            }
            None
        };

        tracing_subscriber::registry()
            .with(console_opt)
            .with(fmt_layer)
            .with(telemetry_layer_opt())
            .with(chrome_layer_opt())
            .init();
        Ok(())
    }
}

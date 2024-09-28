#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! Constants for categorizing the logging type
//!
//! To help stabilize logging targets, avoid typos and improve consistency,
//! it's preferable for logging statements use static target constants,
//! that we define in this module.
//!
//! Core + server side components should use global namespace,
//! while client should generally be prefixed with `client::`.
//! This makes it easier to filter interesting calls when
//! running e.g. `devimint`, that will run both server and client
//! side.

use std::fs::File;
use std::{env, io};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub const LOG_BLOCKCHAIN: &str = "fm::net::blockchain";
pub const LOG_CONSENSUS: &str = "fm::consensus";
pub const LOG_CORE: &str = "fm::core";
pub const LOG_DB: &str = "fm::db";
pub const LOG_DEVIMINT: &str = "fm::devimint";
pub const LOG_NET_API: &str = "fm::net::api";
pub const LOG_NET_PEER_DKG: &str = "fm::net::peer::dkg";
pub const LOG_NET_PEER: &str = "fm::net::peer";
pub const LOG_NET_AUTH: &str = "fm::net::auth";
pub const LOG_TASK: &str = "fm::task";
pub const LOG_RUNTIME: &str = "fm::runtime";
pub const LOG_TEST: &str = "fm::test";
pub const LOG_TIMING: &str = "fm::timing";
pub const LOG_CLIENT: &str = "fm::client";
pub const LOG_CLIENT_DB: &str = "fm::client::db";
pub const LOG_CLIENT_EVENT_LOG: &str = "fm::client::event-log";
pub const LOG_MODULE_MINT: &str = "fm::module::mint";
pub const LOG_MODULE_META: &str = "fm::module::meta";
pub const LOG_MODULE_WALLET: &str = "fm::module::wallet";
pub const LOG_CLIENT_REACTOR: &str = "fm::client::reactor";
pub const LOG_CLIENT_NET_API: &str = "fm::client::net::api";
pub const LOG_CLIENT_BACKUP: &str = "fm::client::backup";
pub const LOG_CLIENT_RECOVERY: &str = "fm::client::recovery";
pub const LOG_CLIENT_RECOVERY_MINT: &str = "fm::client::recovery::mint";
pub const LOG_CLIENT_MODULE_META: &str = "fm::client::module::meta";
pub const LOG_CLIENT_MODULE_MINT: &str = "fm::client::module::mint";
pub const LOG_CLIENT_MODULE_LN: &str = "fm::client::module::ln";
pub const LOG_CLIENT_MODULE_WALLET: &str = "fm::client::module::wallet";

/// Consolidates the setup of server tracing into a helper
#[derive(Default)]
pub struct TracingSetup {
    base_level: Option<String>,
    extra_directives: Option<String>,
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

    /// Sets the log level applied to most modules. Some overly chatty modules
    /// are muted even if this is set to a lower log level, use the `RUST_LOG`
    /// environment variable to override.
    pub fn with_base_level(&mut self, level: impl Into<String>) -> &mut Self {
        self.base_level = Some(level.into());
        self
    }

    /// Add a filter directive.
    pub fn with_directive(&mut self, directive: &str) -> &mut Self {
        if let Some(old) = self.extra_directives.as_mut() {
            *old = format!("{old},{directive}");
        } else {
            self.extra_directives = Some(directive.to_owned());
        }
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
            "{},{},{},{},{},{}",
            self.base_level.as_deref().unwrap_or("info"),
            "jsonrpsee_core::client::async_client=off",
            "jsonrpsee_server=warn,jsonrpsee_server::transport=off",
            "AlephBFT-=error",
            var,
            self.extra_directives.as_deref().unwrap_or(""),
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
                // TODO: https://github.com/fedimint/fedimint/issues/4591
                #[allow(deprecated)]
                let tracer = opentelemetry_jaeger::new_agent_pipeline()
                    .with_service_name("fedimint")
                    .install_simple()
                    .unwrap();

                return Some(tracing_opentelemetry::layer().with_tracer(tracer).boxed());
            }
            None
        };

        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(console_opt())
            .with(telemetry_layer_opt())
            .try_init()?;
        Ok(())
    }
}

pub fn shutdown() {
    #[cfg(feature = "telemetry")]
    opentelemetry::global::shutdown_tracer_provider();
}

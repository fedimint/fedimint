use tokio::sync::OnceCell;

static INSTALL_CRYPTO: OnceCell<()> = OnceCell::const_new();

#[cfg(not(target_family = "wasm"))]
pub async fn install_crypto_provider() {
    use fedimint_logging::LOG_CORE;
    use tracing::warn;

    INSTALL_CRYPTO
        .get_or_init(|| async {
            if tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .is_err()
            {
                warn!(
                    target: LOG_CORE,
                    "Failed to install rustls crypto provider. Hopefully harmless."
                );
            }
        })
        .await;
}

use anyhow::Context;

pub async fn invite_code() -> anyhow::Result<String> {
    let resp = gloo_net::http::Request::get(&url("/connect-string")?)
        .send()
        .await?;
    if resp.ok() {
        Ok(resp.text().await?)
    } else {
        anyhow::bail!(resp.text().await?);
    }
}

pub async fn pay_invoice(invoice: &str) -> anyhow::Result<()> {
    let resp = gloo_net::http::Request::post(&url("/pay")?)
        .body(invoice)?
        .send()
        .await?;
    if resp.ok() {
        Ok(())
    } else {
        anyhow::bail!(resp.text().await?);
    }
}

pub async fn gateway_api() -> anyhow::Result<String> {
    let resp = gloo_net::http::Request::get(&url("/gateway-api")?)
        .send()
        .await?;
    if resp.ok() {
        Ok(resp.text().await?)
    } else {
        anyhow::bail!(resp.text().await?);
    }
}

pub async fn generate_invoice(amt: u64) -> anyhow::Result<String> {
    let resp = gloo_net::http::Request::post(&url("/invoice")?)
        .body(amt)?
        .send()
        .await?;
    if resp.ok() {
        Ok(resp.text().await?)
    } else {
        anyhow::bail!(resp.text().await?);
    }
}

/// Devimint allocates the faucet port when it starts and exports it as
/// `FM_PORT_FAUCET` to the command run via `wasm-test-setup --exec`, which
/// is how it reaches this build. Browser tests have no other way to learn
/// it at runtime.
///
/// Only the wasm build captures it. This crate is also compiled natively
/// as part of `--workspace` builds, frequently from inside a devimint
/// environment, and must not go stale every time devimint hands out a
/// different port.
#[cfg(target_arch = "wasm32")]
const PORT: Option<&str> = option_env!("FM_PORT_FAUCET");
#[cfg(not(target_arch = "wasm32"))]
const PORT: Option<&str> = None;

fn url(path: &str) -> anyhow::Result<String> {
    let port = PORT.context(
        "FM_PORT_FAUCET was not set when fedimint-wasm-tests was built; \
         run the tests via `devimint wasm-test-setup --exec`",
    )?;
    Ok(format!("http://localhost:{port}{path}"))
}

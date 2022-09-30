use anyhow::Error;
use ln_gateway::{cln, LnGateway};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    let mut gateway = LnGateway::new();

    gateway
        .register_ln_rpc(cln::build_cln_rpc)
        .await
        .expect("Failed to register cln rpc");

    gateway.run().await.expect("gateway failed to run");
    Ok(())
}

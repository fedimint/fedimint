use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_wallet::WalletGen;
use fedimintd::distributed_gen::DistributedGen;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    DistributedGen::new()?
        .attach(WalletGen)
        .attach(MintGen)
        .attach(LightningGen)
        .run()
        .await
}

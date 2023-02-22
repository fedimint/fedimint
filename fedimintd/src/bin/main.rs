use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_wallet::WalletGen;
use fedimintd::fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new()?
        .attach(WalletGen)
        .attach(MintGen)
        .attach(LightningGen)
        .run()
        .await
}

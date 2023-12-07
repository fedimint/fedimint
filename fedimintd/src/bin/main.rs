use fedimintd::fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new(env!("FEDIMINT_BUILD_CODE_VERSION"))?
        .with_default_modules()
        .run()
        .await
}

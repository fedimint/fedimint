use fedimintd::fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Fedimintd::new_upstream()?
        .with_default_modules()
        .run()
        .await
}

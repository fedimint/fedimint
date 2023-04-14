use fedimintd::fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Hello, world!");
    Fedimintd::new()?.with_default_modules().run().await
}

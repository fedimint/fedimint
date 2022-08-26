use fedimint_setup::uploads::run_setup;

#[tokio::main]
async fn main() {
    run_setup().await;
}

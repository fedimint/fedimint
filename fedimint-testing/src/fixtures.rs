use std::future::Future;
use std::time::Duration;

use fedimint_client::Client;
use fedimint_core::task::TaskGroup;
use futures::future::join_all;
use tokio::select;

use crate::btc::mock::FakeBitcoinTest;
use crate::btc::BitcoinTest;
use crate::federation::{FederationFixture, FederationTest};

/// Allows users to easily run integration tests
// TODO: Add "real" fixtures
// TODO: Test DB migrations
pub async fn test<F: Future<Output = ()>>(
    mut fed: FederationFixture,
    f: impl FnOnce(FederationTest, Client) -> F,
) {
    let task = TaskGroup::new();
    let mut fed = fed.build(task.make_subgroup().await);
    let client = fed.new_client().await;
    let (servers, handles) = fed.start().await;
    let run = servers
        .into_iter()
        .map(|server| server.run_consensus(task.make_handle()));

    // Runs the test and servers simultaneously
    select! {
        _ = f(fed, client) => {},
        _ = join_all(run) => {},
    }

    for handle in handles {
        handle.stop().await;
    }

    let _ = task.shutdown_join_all(Some(Duration::from_secs(1))).await;
}

pub async fn test_btc<F: Future<Output = ()>>(
    fed: FederationFixture,
    f: impl FnOnce(FederationTest, Client, Box<dyn BitcoinTest>) -> F,
) {
    test(fed, |fed, client| async move {
        f(fed, client, Box::new(FakeBitcoinTest::new())).await;
    })
    .await
}

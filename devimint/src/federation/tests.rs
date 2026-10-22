use std::collections::BTreeMap;
use std::future::ready;

use anyhow::anyhow;

use super::query_running_peers;

#[tokio::test]
async fn running_member_failure_prevents_readiness() {
    let members = BTreeMap::from([(0, true), (1, true), (2, true)]);

    let error = query_running_peers(&members, |peer_id| {
        ready(if peer_id == 1 {
            Err(anyhow!("API unavailable"))
        } else {
            Ok(())
        })
    })
    .await
    .expect_err("a running member's failed query must fail the readiness attempt");

    assert!(
        error.to_string().contains("peer 1 is not online"),
        "error should identify the unavailable running peer: {error:#}"
    );
}

#[tokio::test]
async fn stopped_configured_members_are_excluded_from_readiness() {
    let configured_peer_ids = [0, 1, 2, 3];
    let members = configured_peer_ids
        .into_iter()
        .filter(|peer_id| *peer_id != 2)
        .map(|peer_id| (peer_id, true))
        .collect();
    let mut queried_peer_ids = Vec::new();

    query_running_peers(&members, |peer_id| {
        queried_peer_ids.push(peer_id);
        ready(Ok(()))
    })
    .await
    .expect("all running members respond");

    assert_eq!(queried_peer_ids, [0, 1, 3]);
}

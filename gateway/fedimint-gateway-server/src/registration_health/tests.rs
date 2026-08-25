use std::time::{Duration, UNIX_EPOCH};

use fedimint_core::config::FederationId;
use fedimint_core::runtime::Instant;
use fedimint_gateway_common::{
    RegisteredProtocol, RegistrationAttempt, RegistrationAttemptResult, RegistrationEndpointStatus,
};

use super::RegistrationHealthTracker;

const TTL: Duration = Duration::from_secs(600);

#[tokio::test]
async fn observations_are_isolated_by_federation_and_transport() {
    let tracker = RegistrationHealthTracker::default();
    let first_federation = FederationId::dummy();
    let second_federation = "01".repeat(32).parse().expect("valid federation id");
    let monotonic = Instant::now();

    for (index, (federation_id, protocol, succeeded)) in [
        (first_federation, RegisteredProtocol::Http, true),
        (first_federation, RegisteredProtocol::Iroh, false),
        (second_federation, RegisteredProtocol::Http, false),
        (second_federation, RegisteredProtocol::Iroh, true),
    ]
    .into_iter()
    .enumerate()
    {
        let attempt = tracker.begin_lnv1_attempt(federation_id, protocol);
        tracker
            .complete_attempt(
                attempt,
                succeeded,
                UNIX_EPOCH + Duration::from_secs(index as u64),
                monotonic + Duration::from_secs(index as u64),
            )
            .await;
    }

    for (federation_id, expected_http, expected_iroh) in [
        (
            first_federation,
            RegistrationAttemptResult::Succeeded,
            RegistrationAttemptResult::Failed,
        ),
        (
            second_federation,
            RegistrationAttemptResult::Failed,
            RegistrationAttemptResult::Succeeded,
        ),
    ] {
        let status = tracker
            .lnv1_status(
                federation_id,
                [RegisteredProtocol::Http, RegisteredProtocol::Iroh],
                TTL,
                monotonic + Duration::from_secs(10),
            )
            .await;
        assert_eq!(
            status[&RegisteredProtocol::Http]
                .last_attempt
                .as_ref()
                .expect("HTTP attempt exists")
                .result,
            expected_http
        );
        assert_eq!(
            status[&RegisteredProtocol::Iroh]
                .last_attempt
                .as_ref()
                .expect("Iroh attempt exists")
                .result,
            expected_iroh
        );
    }
}

#[tokio::test]
async fn failed_refresh_preserves_successful_announcement_ttl() {
    let tracker = RegistrationHealthTracker::default();
    let federation_id = FederationId::dummy();
    let monotonic = Instant::now();
    let first = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Http);
    tracker
        .complete_attempt(
            first,
            true,
            UNIX_EPOCH + Duration::from_secs(100),
            monotonic,
        )
        .await;
    let second = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Http);
    tracker
        .complete_attempt(
            second,
            false,
            UNIX_EPOCH + Duration::from_secs(200),
            monotonic + Duration::from_secs(100),
        )
        .await;

    let status = tracker
        .lnv1_status(
            federation_id,
            [RegisteredProtocol::Http],
            TTL,
            monotonic + Duration::from_secs(150),
        )
        .await;
    assert_eq!(
        status.get(&RegisteredProtocol::Http),
        Some(&RegistrationEndpointStatus {
            last_attempt: Some(RegistrationAttempt {
                completed_at_unix_secs: 200,
                result: RegistrationAttemptResult::Failed,
            }),
            advertised_ttl_remaining_secs: Some(450),
        })
    );
}

#[tokio::test]
async fn successful_attempt_and_expired_ttl_are_reported() {
    let tracker = RegistrationHealthTracker::default();
    let federation_id = FederationId::dummy();
    let monotonic = Instant::now();
    let attempt = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Http);
    tracker
        .complete_attempt(
            attempt,
            true,
            UNIX_EPOCH + Duration::from_secs(100),
            monotonic,
        )
        .await;

    let status = tracker
        .lnv1_status(
            federation_id,
            [RegisteredProtocol::Http],
            TTL,
            monotonic + TTL + Duration::from_secs(1),
        )
        .await;
    assert_eq!(
        status.get(&RegisteredProtocol::Http),
        Some(&RegistrationEndpointStatus {
            last_attempt: Some(RegistrationAttempt {
                completed_at_unix_secs: 100,
                result: RegistrationAttemptResult::Succeeded,
            }),
            advertised_ttl_remaining_secs: Some(0),
        })
    );
}

#[tokio::test]
async fn wall_clock_corrections_do_not_change_or_extend_ttl() {
    let tracker = RegistrationHealthTracker::default();
    let federation_id = FederationId::dummy();
    let monotonic = Instant::now();
    let first = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Iroh);
    tracker
        .complete_attempt(
            first,
            true,
            UNIX_EPOCH + Duration::from_secs(10_000),
            monotonic,
        )
        .await;
    let second = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Iroh);
    tracker
        .complete_attempt(
            second,
            true,
            UNIX_EPOCH + Duration::from_secs(1),
            monotonic + Duration::from_secs(100),
        )
        .await;

    let status = tracker
        .lnv1_status(
            federation_id,
            [RegisteredProtocol::Iroh],
            TTL,
            monotonic + Duration::from_secs(150),
        )
        .await;
    assert_eq!(
        status
            .get(&RegisteredProtocol::Iroh)
            .expect("configured transport is present")
            .advertised_ttl_remaining_secs,
        Some(550)
    );
}

#[tokio::test]
async fn older_completion_does_not_replace_newer_attempt_or_success() {
    let tracker = RegistrationHealthTracker::default();
    let federation_id = FederationId::dummy();
    let monotonic = Instant::now();
    let older = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Iroh);
    let newer = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Iroh);
    tracker
        .complete_attempt(
            newer,
            true,
            UNIX_EPOCH + Duration::from_secs(200),
            monotonic,
        )
        .await;
    tracker
        .complete_attempt(
            older,
            true,
            UNIX_EPOCH + Duration::from_secs(300),
            monotonic + Duration::from_secs(100),
        )
        .await;

    let status = tracker
        .lnv1_status(
            federation_id,
            [RegisteredProtocol::Iroh],
            TTL,
            monotonic + Duration::from_secs(150),
        )
        .await;
    assert_eq!(
        status.get(&RegisteredProtocol::Iroh),
        Some(&RegistrationEndpointStatus {
            last_attempt: Some(RegistrationAttempt {
                completed_at_unix_secs: 200,
                result: RegistrationAttemptResult::Succeeded,
            }),
            advertised_ttl_remaining_secs: Some(450),
        })
    );
}

#[tokio::test]
async fn configured_transport_without_attempt_has_unknown_result_and_ttl() {
    let tracker = RegistrationHealthTracker::default();
    let status = tracker
        .lnv1_status(
            FederationId::dummy(),
            [RegisteredProtocol::Http],
            TTL,
            Instant::now(),
        )
        .await;
    assert_eq!(
        status.get(&RegisteredProtocol::Http),
        Some(&RegistrationEndpointStatus {
            last_attempt: None,
            advertised_ttl_remaining_secs: None,
        })
    );
}

#[tokio::test]
async fn clear_rejects_stale_completion_but_accepts_rejoin_attempt() {
    let tracker = RegistrationHealthTracker::default();
    let federation_id = FederationId::dummy();
    let monotonic = Instant::now();
    let stale_attempt = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Http);
    tracker.clear_federation(federation_id).await;
    tracker
        .complete_attempt(
            stale_attempt,
            true,
            UNIX_EPOCH + Duration::from_secs(100),
            monotonic,
        )
        .await;
    let rejoin_attempt = tracker.begin_lnv1_attempt(federation_id, RegisteredProtocol::Http);
    tracker
        .complete_attempt(
            rejoin_attempt,
            true,
            UNIX_EPOCH + Duration::from_secs(200),
            monotonic + Duration::from_secs(10),
        )
        .await;

    let status = tracker
        .lnv1_status(
            federation_id,
            [RegisteredProtocol::Http],
            TTL,
            monotonic + Duration::from_secs(20),
        )
        .await;
    assert_eq!(
        status.get(&RegisteredProtocol::Http),
        Some(&RegistrationEndpointStatus {
            last_attempt: Some(RegistrationAttempt {
                completed_at_unix_secs: 200,
                result: RegistrationAttemptResult::Succeeded,
            }),
            advertised_ttl_remaining_secs: Some(590),
        })
    );
}

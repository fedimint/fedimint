use assert_matches::assert_matches;
use fedimint_connectors::error::ServerError;
use fedimint_core::{NumPeers, PeerId};

use super::{QueryStep, QueryStrategy, ThresholdAgreement, ThresholdConsensus};

fn dead_peer() -> ServerError {
    ServerError::Connection("peer is unreachable".into())
}

#[tokio::test]
async fn threshold_agreement_counts_every_peer() {
    // The case `FilterMapThreshold` gets wrong: peer 0 lags, and the agreement
    // among 1, 2 and 3 only becomes visible once the fourth answer lands. A
    // strategy that stopped at `threshold` responses would have reported a
    // divergence that does not exist.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(
        agreement.process(PeerId::from(0), 0).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(3), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(2), 1).await,
        QueryStep::Success(Ok(1))
    );
}

#[tokio::test]
async fn threshold_agreement_reports_divergence_once_every_peer_has_answered() {
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(
        agreement.process(PeerId::from(0), 0).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(2), 2).await,
        QueryStep::Continue
    );

    let QueryStep::Success(Err(responses)) = agreement.process(PeerId::from(3), 3).await else {
        panic!("expected a divergence carrying every response");
    };
    assert_eq!(responses.len(), 4);
}

#[tokio::test]
async fn threshold_agreement_does_not_wait_on_a_peer_that_errored() {
    // A failed peer completes the picture just as a response does, so the
    // divergence is reported rather than waiting on an answer that is never
    // coming - the hang this strategy exists to avoid.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(
        agreement.process(PeerId::from(0), 0).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(2), 1).await,
        QueryStep::Continue
    );

    let QueryStep::Success(Err(responses)) = agreement.process_error(PeerId::from(3), &dead_peer())
    else {
        panic!("expected a divergence once every peer has answered");
    };
    assert_eq!(responses.len(), 3);
}

#[tokio::test]
async fn threshold_agreement_defers_to_peer_errors_when_too_few_answered() {
    // Two of four unreachable leaves fewer responses than the threshold. The
    // useful complaint is that peers are down, which the caller reports from
    // its own error accounting, so stay quiet.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(
        agreement.process(PeerId::from(0), 0).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process_error(PeerId::from(2), &dead_peer()),
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process_error(PeerId::from(3), &dead_peer()),
        QueryStep::Continue
    );
}

#[tokio::test]
async fn test_threshold_consensus() {
    let mut consensus = ThresholdConsensus::<u64>::new(NumPeers::from(4));

    assert_matches!(
        consensus.process(PeerId::from(0), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        consensus.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        consensus.process(PeerId::from(2), 0).await,
        QueryStep::Retry(..)
    );

    assert_matches!(
        consensus.process(PeerId::from(0), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        consensus.process(PeerId::from(1), 1).await,
        QueryStep::Continue
    );
    assert_matches!(
        consensus.process(PeerId::from(2), 1).await,
        QueryStep::Success(1)
    );
}

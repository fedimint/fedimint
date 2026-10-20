use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, ScriptBuf, Txid};
use fedimint_walletv2_common::{MempoolVisibility, PendingOutput, PendingOutputs};

use super::merge_pending_outputs;

/// The threshold of a four guardian federation.
const THRESHOLD: usize = 3;

fn outpoint(n: u8) -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: Txid::from_byte_array([n; 32]),
        vout: 0,
    }
}

fn output(n: u8, height: Option<u64>) -> PendingOutput {
    PendingOutput {
        script: ScriptBuf::new(),
        outpoint: outpoint(n),
        value: Amount::from_sat(u64::from(n) * 1_000),
        height,
    }
}

fn response(
    block_count: u64,
    outputs: Vec<PendingOutput>,
    mempool_visibility: MempoolVisibility,
) -> PendingOutputs {
    PendingOutputs {
        block_count,
        outputs,
        mempool_visibility,
    }
}

/// A response that only contributes a chain tip.
fn tip(block_count: u64) -> PendingOutputs {
    response(block_count, vec![], MempoolVisibility::Unavailable)
}

#[test]
fn block_count_is_the_highest_a_threshold_of_peers_reached() {
    // Peer order must not matter, and a single peer far ahead must not drag
    // everyone's progress along with it.
    let merged = merge_pending_outputs(vec![tip(101), tip(500), tip(100), tip(102)], THRESHOLD);

    assert_eq!(merged.block_count, 101);
}

#[test]
fn block_count_falls_back_to_the_highest_tip_below_a_threshold() {
    // Fewer than a threshold of guardians serve the endpoint, as on a partially
    // upgraded federation, so no tip is backed by a threshold.
    let merged = merge_pending_outputs(vec![tip(100), tip(105)], THRESHOLD);

    assert_eq!(merged.block_count, 105);
}

#[test]
fn no_responses_merge_into_an_empty_blind_view() {
    let merged = merge_pending_outputs(vec![], THRESHOLD);

    assert_eq!(merged, PendingOutputs::default());
    assert_eq!(merged.mempool_visibility, MempoolVisibility::Unavailable);
}

#[test]
fn a_mined_height_wins_over_a_mempool_sighting_in_either_order() {
    let mempool = response(100, vec![output(1, None)], MempoolVisibility::Complete);
    let mined = response(
        100,
        vec![output(1, Some(95))],
        MempoolVisibility::Unavailable,
    );

    for responses in [
        vec![mempool.clone(), mined.clone()],
        vec![mined.clone(), mempool.clone()],
    ] {
        let merged = merge_pending_outputs(responses, THRESHOLD);

        assert_eq!(
            merged.outputs,
            vec![output(1, Some(95))],
            "The duplicate must collapse into one mined output"
        );
    }
}

#[test]
fn conflicting_heights_keep_the_highest_in_either_order() {
    // Across a reorg one guardian can have the deposit in an older block than
    // another. The higher block yields fewer confirmations, so keeping it never
    // overstates progress.
    let older = response(
        100,
        vec![output(1, Some(95))],
        MempoolVisibility::Unavailable,
    );
    let newer = response(
        100,
        vec![output(1, Some(97))],
        MempoolVisibility::Unavailable,
    );

    for responses in [
        vec![older.clone(), newer.clone()],
        vec![newer.clone(), older.clone()],
    ] {
        let merged = merge_pending_outputs(responses, THRESHOLD);

        assert_eq!(merged.outputs, vec![output(1, Some(97))]);
    }
}

#[test]
fn outputs_from_different_peers_are_unioned_by_outpoint() {
    let merged = merge_pending_outputs(
        vec![
            response(
                100,
                vec![output(3, Some(98)), output(1, None)],
                MempoolVisibility::Complete,
            ),
            response(
                100,
                vec![output(2, Some(99))],
                MempoolVisibility::Unavailable,
            ),
        ],
        THRESHOLD,
    );

    assert_eq!(
        merged.outputs,
        vec![output(1, None), output(2, Some(99)), output(3, Some(98))],
        "Every distinct outpoint is kept once, ordered by outpoint"
    );
}

#[test]
fn mempool_visibility_is_the_best_any_peer_had() {
    use MempoolVisibility::{Complete, Partial, Unavailable};

    for (visibilities, expected) in [
        (vec![Unavailable, Unavailable], Unavailable),
        (vec![Unavailable, Partial, Unavailable], Partial),
        (vec![Partial, Complete, Unavailable], Complete),
        (vec![Complete, Partial], Complete),
    ] {
        let responses = visibilities
            .iter()
            .map(|visibility| response(100, vec![], *visibility))
            .collect();

        assert_eq!(
            merge_pending_outputs(responses, THRESHOLD).mempool_visibility,
            expected,
            "Merging {visibilities:?}"
        );
    }
}

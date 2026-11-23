use super::*;

#[test]
fn confirmations_reach_required_exactly_when_claimable() {
    for finality_delay in [0, 2, 10] {
        let required = required_confirmations(finality_delay);
        for tx_block_count in [1, 2, 6, 101] {
            for consensus_block_count in 0..130 {
                assert_eq!(
                    deposit_confirmations(tx_block_count, consensus_block_count, finality_delay)
                        == required,
                    blocks_until_claimable(tx_block_count, consensus_block_count) == 0,
                    "finality_delay={finality_delay} tx_block_count={tx_block_count} \
                     consensus_block_count={consensus_block_count}"
                );
            }
        }
    }
}

#[test]
fn confirmations_count_the_block_that_mined_the_deposit() {
    // Guardians vote 10 below their block count of 105, so the consensus block
    // count is 95. A deposit in the tip block, at height 104, has one
    // confirmation and one at height 102 has three.
    assert_eq!(deposit_confirmations(105, 95, 10), 1);
    assert_eq!(deposit_confirmations(103, 95, 10), 3);
    // The guardians have not seen the block yet.
    assert_eq!(deposit_confirmations(106, 95, 10), 0);
    assert_eq!(deposit_confirmations(200, 95, 10), 0);
    // Stops at the target however deep the deposit gets.
    assert_eq!(deposit_confirmations(50, 95, 10), 11);
}

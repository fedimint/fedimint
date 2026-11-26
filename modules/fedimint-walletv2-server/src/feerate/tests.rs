use super::FeeRateUse::{Consensus, Quote};
use super::NumPeers;

#[test]
fn quotes_require_support_from_the_available_votes() {
    for total in 1..=32 {
        let peers = NumPeers::from(total);
        for present in 0..=total {
            let mut votes: Vec<_> = (1..=present as u64).rev().collect();
            let required = (present >= peers.threshold()).then_some(peers.threshold() as u64);
            assert_eq!(Consensus.select(peers, &mut votes, 0), required);
            assert_eq!(
                Quote.select(peers, &mut votes, 0),
                required.filter(
                    |rate| votes.iter().filter(|vote| *vote >= rate).count() > peers.max_evil()
                )
            );
        }
    }
}

#[test]
fn partial_agreement_or_the_pending_stack_floor_can_support_a_quote() {
    let peers = NumPeers::from(4);
    assert_eq!(Quote.select(peers, &mut [10, 20, 20], 0), Some(20));
    assert_eq!(Quote.select(peers, &mut [10, 20, 30], 29), None);
    assert_eq!(Quote.select(peers, &mut [10, 20, 30], 30), Some(30));
    assert_eq!(Quote.select(peers, &mut [10, 20], 30), None);
}

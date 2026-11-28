use fedimint_core::NumPeers;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(super) enum FeeRateUse {
    Consensus,
    Quote,
}

impl FeeRateUse {
    /// Select the required rate, optionally checking that it is safe to quote.
    pub(super) fn select(self, peers: NumPeers, votes: &mut [u64], floor: u64) -> Option<u64> {
        assert!(votes.len() <= peers.total());
        votes.sort_unstable();

        // This rank is part of transaction validation, including historical replay.
        let required = (*votes.get(peers.threshold() - 1)?).max(floor);

        if let Self::Quote = self {
            // Count from the high end of the *present* votes. At least one of the
            // highest f+1 estimates is honest. With a full set this is exactly
            // the consensus rank; with missing estimates it can be lower.
            let supported = votes[votes.len() - peers.one_honest()].max(floor);
            if required > supported {
                // Quoting the lower rate would produce an invalid transaction.
                return None;
            }
        }

        Some(required)
    }
}

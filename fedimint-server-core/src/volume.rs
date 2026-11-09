//! Windows over the per-day volume counters that modules keep.

/// Map a module's consensus block count to its 144-block volume bucket.
pub fn volume_day(block_count: u64) -> u64 {
    block_count / 144
}

/// Bucket numbers included in a report, ending with the current bucket.
pub fn volume_buckets(block_count: u64, days: u64) -> std::ops::Range<u64> {
    let end = volume_day(block_count) + 1;
    end.saturating_sub(days)..end
}

/// A guardian that upgraded during the first bucket may have missed flows,
/// even if it started counting at that bucket's first block. Zero is the
/// start marker for a guardian that counted from formation.
pub fn counted_whole_window(start_block: Option<u64>, first_bucket: u64) -> bool {
    match start_block {
        None => false,
        Some(0) => true,
        Some(start) => volume_day(start) < first_bucket,
    }
}

#[cfg(test)]
mod tests;

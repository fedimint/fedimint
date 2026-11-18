//! Windows over the per-bucket volume counters that modules keep.

/// The number of module consensus blocks in one volume bucket.
pub const VOLUME_BUCKET_BLOCKS: u64 = 144;

/// Map a module's consensus block count to its volume bucket.
pub fn volume_bucket(block_count: u64) -> u64 {
    block_count / VOLUME_BUCKET_BLOCKS
}

/// The last `buckets` complete buckets before the current one. Leaving out the
/// unfinished bucket makes a window cover exactly `buckets` buckets, and every
/// guardian in the same bucket reports the same window.
pub fn volume_buckets(block_count: u64, buckets: u64) -> std::ops::Range<u64> {
    let end = volume_bucket(block_count);
    end.saturating_sub(buckets)..end
}

/// A guardian that upgraded during the first bucket may have missed flows,
/// even if it started counting at that bucket's first block. Zero is the
/// start marker for a guardian that counted from formation.
pub fn counted_whole_window(start_block: Option<u64>, first_bucket: u64) -> bool {
    match start_block {
        None => false,
        Some(0) => true,
        Some(start) => volume_bucket(start) < first_bucket,
    }
}

#[cfg(test)]
mod tests;

//! Which receive addresses are still handed out, which of them are reserved,
//! and whether a recovery has yet to find out which of them were paid.
//!
//! Everything here reads and writes inside the caller's transaction. That is
//! what keeps a reservation and the discovery of a payment apart: both write
//! [`LowestUnusedAddressIndexKey`], so of two such transactions that overlap
//! only one commits, and the other is retried against what the first left.

use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt;

use crate::db::{
    LowestUnusedAddressIndexKey, RecoveryScan, RecoveryScanKey, ReservedAddress,
    ReservedAddressKey, ValidAddressIndexPrefix,
};
use crate::{MAX_UNPAID_RESERVATIONS, ReserveAddressError};

/// The valid address indices that are still handed out: those from
/// [`LowestUnusedAddressIndexKey`] on.
pub(crate) struct AddressWindow {
    /// How many of them there are.
    pub(crate) len: usize,
    /// How many of them are reserved.
    pub(crate) reserved: usize,
    /// The lowest of them that is not reserved.
    pub(crate) unused: Option<u64>,
    /// Where the search for the next valid index starts.
    pub(crate) next_index: u64,
}

impl AddressWindow {
    pub(crate) async fn load<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> Self
    where
        Cap: Send,
    {
        let lowest_unused = lowest_unused(dbtx).await;

        let mut valid_indices: Vec<u64> = dbtx
            .find_by_prefix(&ValidAddressIndexPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        valid_indices.sort_unstable();

        let mut window = Self {
            len: 0,
            reserved: 0,
            unused: None,
            next_index: valid_indices.last().map_or(0, |index| index + 1),
        };

        for index in valid_indices {
            if index < lowest_unused {
                continue;
            }

            window.len += 1;

            if dbtx.get_value(&ReservedAddressKey(index)).await.is_some() {
                window.reserved += 1;
            } else if window.unused.is_none() {
                window.unused = Some(index);
            }
        }

        window
    }
}

async fn lowest_unused<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> u64
where
    Cap: Send,
{
    dbtx.get_value(&LowestUnusedAddressIndexKey)
        .await
        .unwrap_or(0)
}

/// The lowest address index that is neither paid nor reserved. There is none
/// to hand out while the scanner has not derived one, or while a recovery has
/// yet to establish which addresses were paid.
pub(crate) async fn unused<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> Option<u64>
where
    Cap: Send,
{
    if recovery_scanning(dbtx).await {
        return None;
    }

    AddressWindow::load(dbtx).await.unused
}

/// Starts a recovery's scan of the federation's outputs, unless the wallet's
/// recovery has started it before, whether or not it is over.
pub(crate) async fn start_recovery_scan<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>)
where
    Cap: Send,
{
    if dbtx.get_value(&RecoveryScanKey).await.is_none() {
        dbtx.insert_entry(&RecoveryScanKey, &RecoveryScan::Scanning)
            .await;
    }
}

/// Whether a recovery's scan of the federation's outputs is under way.
pub(crate) async fn recovery_scanning<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> bool
where
    Cap: Send,
{
    dbtx.get_value(&RecoveryScanKey).await == Some(RecoveryScan::Scanning)
}

/// Ends a recovery's scan of the federation's outputs. Returns whether one
/// was under way.
pub(crate) async fn finish_recovery_scan<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>) -> bool
where
    Cap: Send,
{
    if !recovery_scanning(dbtx).await {
        return false;
    }

    dbtx.insert_entry(&RecoveryScanKey, &RecoveryScan::Complete)
        .await;

    true
}

/// Reserves the lowest unused address index for `operation_id` and returns
/// it, or `None` if there is none to hand out yet.
pub(crate) async fn reserve<Cap>(
    dbtx: &mut DatabaseTransaction<'_, Cap>,
    operation_id: OperationId,
) -> Result<Option<u64>, ReserveAddressError>
where
    Cap: Send,
{
    let lowest_unused = lowest_unused(dbtx).await;

    if MAX_UNPAID_RESERVATIONS <= AddressWindow::load(dbtx).await.reserved {
        return Err(ReserveAddressError::TooManyUnpaid);
    }

    let Some(address_index) = unused(dbtx).await else {
        return Ok(None);
    };

    dbtx.insert_new_entry(
        &ReservedAddressKey(address_index),
        &ReservedAddress {
            operation_id,
            claim: None,
        },
    )
    .await;

    // Written back unchanged: a transaction that found a payment to the
    // address meanwhile moves this, and the two then conflict.
    dbtx.insert_entry(&LowestUnusedAddressIndexKey, &lowest_unused)
        .await;

    Ok(Some(address_index))
}

/// Records that a payment to the address at `address_index` was found, so
/// that neither it nor any address below it is handed out again. Returns
/// whether that changed anything.
pub(crate) async fn retire<Cap>(dbtx: &mut DatabaseTransaction<'_, Cap>, address_index: u64) -> bool
where
    Cap: Send,
{
    if address_index < lowest_unused(dbtx).await {
        return false;
    }

    dbtx.insert_entry(&LowestUnusedAddressIndexKey, &(address_index + 1))
        .await;

    true
}

#[cfg(test)]
mod tests;

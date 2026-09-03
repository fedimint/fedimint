use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    NextOutputIndex = 0x31,
    ValidAddressIndex = 0x32,
    PendingReceive = 0x33,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct NextOutputIndexKey;

impl_db_record!(
    key = NextOutputIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextOutputIndex
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ValidAddressIndexKey(pub u64);

impl_db_record!(
    key = ValidAddressIndexKey,
    value = (),
    db_prefix = DbKeyPrefix::ValidAddressIndex
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ValidAddressIndexPrefix;

impl_db_lookup!(
    key = ValidAddressIndexKey,
    query_prefix = ValidAddressIndexPrefix
);

/// A peg-in to one of our addresses that the federation can see but has not yet
/// recorded in its consensus output log.
///
/// Keyed per outpoint rather than per address, because nothing stops an address
/// being paid more than once: [`receive`] hands out the same address until a
/// deposit is detected at it, so two deposits before the first is seen is an
/// ordinary flow. Collapsing them would silently drop one from the progress
/// view.
///
/// This table is rebuilt wholesale on every scan rather than appended to. The
/// underlying data is advisory and revocable: an entry must disappear if a
/// reorg unmines it or the mempool drops it, and once the output graduates into
/// the consensus output log the real receive operation takes over.
///
/// [`receive`]: crate::WalletClientModule::receive
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingReceiveKey {
    /// Encoded first so that [`PendingReceiveAddressPrefix`] can range over
    /// every deposit to one address.
    pub address_index: u64,
    pub outpoint: bitcoin::OutPoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct PendingReceive {
    pub value: bitcoin::Amount,
    /// Height of the block that mined the peg-in, or `None` while it is only
    /// in a guardian's mempool.
    pub height: Option<u64>,
    /// Chain tip the confirmation count is relative to, as reported by the
    /// federation when this entry was written.
    pub block_count: u64,
}

impl PendingReceive {
    /// Confirmations using the standard Bitcoin convention, where the block
    /// that mines a transaction counts as the first confirmation.
    ///
    /// `None` for a peg-in that is still unmined.
    pub fn confirmations(&self) -> Option<u64> {
        Some(self.block_count.saturating_sub(self.height?))
    }
}

impl_db_record!(
    key = PendingReceiveKey,
    value = PendingReceive,
    db_prefix = DbKeyPrefix::PendingReceive
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingReceivePrefix;

/// Ranges over every pending deposit to a single receive address.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingReceiveAddressPrefix(pub u64);

impl_db_lookup!(
    key = PendingReceiveKey,
    query_prefix = PendingReceivePrefix,
    query_prefix = PendingReceiveAddressPrefix,
);

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_mintv2_common::Denomination;
use strum::Display;
use strum_macros::EnumIter;

use crate::SpendableNote;

#[repr(u8)]
#[derive(Clone, Display, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteKey(pub SpendableNote);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteAmountPrefix(pub Denomination);

impl_db_record!(
    key = SpendableNoteKey,
    value = (),
    db_prefix = DbKeyPrefix::Note,
);

impl_db_lookup!(key = SpendableNoteKey, query_prefix = SpendableNotePrefix);

impl_db_lookup!(
    key = SpendableNoteKey,
    query_prefix = SpendableNoteAmountPrefix
);

use std::io::Cursor;

use fedimint_core::core::OperationId;
use fedimint_core::db::{IDatabaseTransactionOpsCoreTyped, WriteDatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{Amount, TransactionId, impl_db_lookup, impl_db_record};
use strum_macros::EnumIter;
use tracing::warn;

use crate::states::{DummyStateMachine, DummyStateMachineV1};

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    ClientFunds = 0x04,
    // Used to verify that 0x50 key can be written to, which used to conflict with
    // `DatabaseVersionKeyV0`
    ClientName = 0x50,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedEnd = 0xff,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV0;

impl_db_record!(
    key = DummyClientFundsKeyV0,
    value = (),
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV1;

impl_db_record!(
    key = DummyClientFundsKeyV1,
    value = Amount,
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKey {
    pub unit: AmountUnit,
}

impl_db_record!(
    key = DummyClientFundsKey,
    value = Amount,
    db_prefix = DbKeyPrefix::ClientFunds,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientFundsKeyV2PrefixAll;

impl_db_lookup!(
    key = DummyClientFundsKey,
    query_prefix = DummyClientFundsKeyV2PrefixAll,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientNameKey;

impl_db_record!(
    key = DummyClientNameKey,
    value = String,
    db_prefix = DbKeyPrefix::ClientName,
);

/// Migrates the database from version 0 to version 1 by
/// removing `DummyClientFundsKeyV0` and inserting `DummyClientFundsKeyV1`.
/// The new key/value pair has an `Amount` as the value.
pub async fn migrate_to_v1(
    dbtx: &mut WriteDatabaseTransaction<'_>,
) -> anyhow::Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>> {
    if dbtx.remove_entry(&DummyClientFundsKeyV0).await.is_some() {
        // Since this is a dummy migration, we can insert any value for the client
        // funds. Real modules should handle the funds properly.

        dbtx.insert_new_entry(&DummyClientFundsKeyV1, &Amount::from_sats(1000))
            .await;
    } else {
        warn!("Dummy client did not have client funds, skipping database migration");
    }

    Ok(None)
}

/// Maps all `Unreachable` states in the state machine to `OutputDone`
pub(crate) fn get_v1_migrated_state(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();
    let dummy_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    // We are only migrating the type of one of the variants, so we do nothing on
    // other discriminants.
    if dummy_sm_variant != 5 {
        return Ok(None);
    }

    let _unreachable_state_length = u16::consensus_decode_partial(cursor, &decoders)?;

    // Migrate `Unreachable` states to `OutputDone`
    let unreachable = Unreachable::consensus_decode_partial(cursor, &decoders)?;
    let new_state = DummyStateMachineV1::OutputDone(
        unreachable.amount,
        unreachable.txid,
        unreachable.operation_id,
    );
    let bytes = new_state.consensus_encode_to_vec();
    Ok(Some((bytes, operation_id)))
}

/// [`AmountUnit`] was added to the state
pub(crate) fn get_v2_migrated_state(
    operation_id: OperationId,
    cursor: &mut Cursor<&[u8]>,
) -> anyhow::Result<Option<(Vec<u8>, OperationId)>> {
    let decoders = ModuleDecoderRegistry::default();
    let dummy_sm_variant = u16::consensus_decode_partial(cursor, &decoders)?;

    let _state_length = u16::consensus_decode_partial(cursor, &decoders)?;

    match dummy_sm_variant {
        0 | 1 | 3 => {}
        _ => {
            return Ok(None);
        }
    }

    let (amount, txid, op_id) =
        <(Amount, TransactionId, OperationId)>::consensus_decode_partial(cursor, &decoders)?;

    // TODO: should this be the case? Does not seem like it.
    // debug_assert_eq!(operation_id, op_id);

    let bytes = match dummy_sm_variant {
        0 => DummyStateMachine::Input(amount, AmountUnit::BITCOIN, txid, op_id)
            .consensus_encode_to_vec(),
        1 => DummyStateMachine::Output(amount, AmountUnit::BITCOIN, txid, op_id)
            .consensus_encode_to_vec(),
        3 => DummyStateMachine::OutputDone(amount, AmountUnit::BITCOIN, txid, op_id)
            .consensus_encode_to_vec(),
        _ => unreachable!(),
    };

    debug_assert!(DummyStateMachine::consensus_decode_whole(&bytes, &decoders).is_ok());

    Ok(Some((bytes, operation_id)))
}

#[derive(Debug)]
struct Unreachable {
    operation_id: OperationId,
    txid: TransactionId,
    amount: Amount,
}

impl Decodable for Unreachable {
    fn consensus_decode_partial<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let operation_id = OperationId::consensus_decode_partial(reader, modules)?;
        let txid = TransactionId::consensus_decode_partial(reader, modules)?;
        let amount = Amount::consensus_decode_partial(reader, modules)?;

        Ok(Unreachable {
            operation_id,
            txid,
            amount,
        })
    }
}

use std::io::Cursor;

use fedimint_core::db::Database;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};

use crate::SignedBlock;

#[derive(Debug, Encodable, Decodable)]
pub struct SignedBlockKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct SignedBlockPrefix;

impl_db_record!(
    key = SignedBlockKey,
    value = SignedBlock,
    db_prefix = 0x04,
    notify_on_modify = false,
);
impl_db_lookup!(key = SignedBlockKey, query_prefix = SignedBlockPrefix);

#[derive(Debug, Encodable, Decodable)]
struct UnitsKey(u64, u64);

impl_db_record!(
    key = UnitsKey,
    value = Vec<u8>,
    db_prefix = 0x05,
    notify_on_modify = false,
);

pub async fn load_block(db: &Database, index: u64) -> Option<SignedBlock> {
    db.begin_transaction()
        .await
        .get_value(&SignedBlockKey(index))
        .await
}

/// This function loads the aleph bft backup from disk and creates a UnitSaver
/// instance which allows aleph bft to append further bytes to the existing
/// backup
pub async fn open_session(db: Database, session_index: u64) -> (Cursor<Vec<u8>>, UnitSaver) {
    let mut buffer = vec![];
    let mut units_index = 0;
    let mut dbtx = db.begin_transaction().await;

    while let Some(bytes) = dbtx.get_value(&UnitsKey(session_index, units_index)).await {
        buffer.extend(bytes);
        units_index += 1;
    }

    std::mem::drop(dbtx);

    tracing::info!("Loaded aleph buffer with {} bytes", buffer.len());

    // the cursor enables aleph bft to read the units via std::io::Read
    let unit_loader = Cursor::new(buffer);

    // we pass the first free unit index to the UnitSaver as an offset
    let unit_saver = UnitSaver::new(db, session_index, units_index);

    (unit_loader, unit_saver)
}

/// The UnitSaver enables aleph bft to store its local directed acyclic graph of
/// units on disk in order to recover from a mid session crash. By implementing
/// std::io::Write we allow aleph bft to append bytes to its existing backup
/// similar to a open file in append mode.
pub struct UnitSaver {
    db: Database,
    session_index: u64,
    units_index: u64,
    buffer: Vec<u8>,
}

impl UnitSaver {
    fn new(db: Database, session_index: u64, units_index: u64) -> Self {
        Self {
            db,
            session_index,
            units_index,
            buffer: vec![],
        }
    }
}

impl std::io::Write for UnitSaver {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let units_key = UnitsKey(self.session_index, self.units_index);

        futures::executor::block_on(async {
            let mut dbtx = self.db.begin_transaction().await;

            dbtx.insert_new_entry(&units_key, &self.buffer).await;

            dbtx.commit_tx_result()
                .await
                .expect("This is the only place where we write to this key");
        });

        self.buffer.clear();
        self.units_index += 1;

        Ok(())
    }
}

/// The function removes the units stored by aleph bft and stores the signed
/// block instead
pub async fn complete_session(db: &Database, index: u64, signed_block: SignedBlock) {
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_new_entry(&SignedBlockKey(index), &signed_block)
        .await;

    let mut units_index = 0;

    while dbtx
        .remove_entry(&UnitsKey(index, units_index))
        .await
        .is_some()
    {
        units_index += 1;
    }

    dbtx.commit_tx_result()
        .await
        .expect("The function is only called after we have terminated the aleph session");
}

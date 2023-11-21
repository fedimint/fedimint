use std::io::Cursor;

use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};

use crate::db::AlephUnitsKey;
use crate::LOG_CONSENSUS;

/// This function loads the aleph bft backup from disk and creates a UnitSaver
/// instance which allows aleph bft to append further bytes to the existing
/// backup
pub async fn load_session(db: Database) -> (Cursor<Vec<u8>>, UnitSaver) {
    let mut buffer = vec![];
    let mut units_index = 0;
    let mut dbtx = db.begin_transaction().await;

    while let Some(bytes) = dbtx.get_value(&AlephUnitsKey(units_index)).await {
        buffer.extend(bytes);
        units_index += 1;
    }

    std::mem::drop(dbtx);

    if !buffer.is_empty() {
        tracing::info!(target: LOG_CONSENSUS, buffer_len = %buffer.len(), "Recovering from an in-session-shutdown");
    }

    // the cursor enables aleph bft to read the units via std::io::Read
    let unit_loader = Cursor::new(buffer);

    // we pass the first free unit index to the UnitSaver as an offset
    let unit_saver = UnitSaver::new(db, units_index);

    (unit_loader, unit_saver)
}

/// The UnitSaver enables aleph bft to store its local directed acyclic graph of
/// units on disk in order to recover from a mid session crash. By implementing
/// std::io::Write we allow aleph bft to append bytes to its existing backup
/// similar to a open file in append mode.
pub struct UnitSaver {
    db: Database,
    units_index: u64,
    buffer: Vec<u8>,
}

impl UnitSaver {
    fn new(db: Database, units_index: u64) -> Self {
        Self {
            db,
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
        futures::executor::block_on(async {
            let mut dbtx = self.db.begin_transaction().await;

            dbtx.insert_new_entry(&AlephUnitsKey(self.units_index), &self.buffer)
                .await;

            dbtx.commit_tx_result()
                .await
                .expect("This is the only place where we write to this key");
        });

        self.buffer.clear();
        self.units_index += 1;

        Ok(())
    }
}

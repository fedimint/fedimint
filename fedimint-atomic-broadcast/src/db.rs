use std::io::Cursor;

use fedimint_core::{
    db::Database,
    encoding::{Decodable, Encodable},
    impl_db_record,
};

use crate::SignedBlock;

#[derive(Debug, Encodable, Decodable)]
struct SignedBlockKey(u64);

impl_db_record!(
    key = SignedBlockKey,
    value = SignedBlock,
    db_prefix = 0x00,
    notify_on_modify = false,
);

#[derive(Debug, Encodable, Decodable)]
struct AlephBufferKey(u64, u64);

impl_db_record!(
    key = AlephBufferKey,
    value = Vec<u8>,
    db_prefix = 0x01,
    notify_on_modify = false,
);

pub async fn load_block(db: &Database, index: u64) -> Option<SignedBlock> {
    db.begin_transaction()
        .await
        .get_value(&SignedBlockKey(index))
        .await
}

pub async fn open_session(db: Database, index: u64) -> (Cursor<Vec<u8>>, UnitSaver) {
    let mut buffer = vec![];
    let mut buffer_index = 0;
    let mut transaction = db.begin_transaction().await;

    while let Some(bytes) = transaction
        .get_value(&AlephBufferKey(index, buffer_index))
        .await
    {
        buffer.extend(bytes);
        buffer_index += 1;
    }

    std::mem::drop(transaction);

    tracing::info!("Loaded aleph buffer with {} bytes", buffer.len());

    // the cursor enables aleph bft to read all previously flushed bytes via std::io::Read
    let loader = Cursor::new(buffer);

    // aleph bft expects bytes written via the saver to be appended to the bytes previously read
    // via the loader - hence we pass the first free buffer index to the UnitSaver as an offset
    let saver = UnitSaver::new(db, index, buffer_index);

    (loader, saver)
}

pub struct UnitSaver {
    db: Database,
    index: u64,
    buffer_index: u64,
    buffer: Vec<u8>,
}

impl UnitSaver {
    fn new(db: Database, index: u64, buffer_index: u64) -> Self {
        Self {
            db,
            index,
            buffer_index,
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
        let buffer_key = AlephBufferKey(self.index, self.buffer_index);

        futures::executor::block_on(async {
            let mut transaction = self.db.begin_transaction().await;

            transaction
                .insert_new_entry(&buffer_key, &self.buffer)
                .await;

            transaction
                .commit_tx_result()
                .await
                .expect("This is the only place where we write to this key");
        });

        self.buffer.clear();
        self.buffer_index += 1;

        Ok(())
    }
}

pub async fn complete_session(db: &Database, index: u64, signed_block: SignedBlock) {
    let mut transaction = db.begin_transaction().await;

    transaction
        .insert_new_entry(&SignedBlockKey(index), &signed_block)
        .await;

    let mut buffer_index = 0;

    while transaction
        .remove_entry(&AlephBufferKey(index, buffer_index))
        .await
        .is_some()
    {
        buffer_index += 1;
    }

    transaction
        .commit_tx_result()
        .await
        .expect("The function is only called after we have terminated the aleph session");
}

use std::pin::pin;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, PubkeyHash, ScriptBuf, TxOut, WScriptHash};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::poll;

use crate::await_outputs;
use crate::db::{Output, OutputKey};

fn output(script_pubkey: ScriptBuf) -> Output {
    Output(
        bitcoin::OutPoint::null(),
        TxOut {
            value: Amount::ONE_SAT,
            script_pubkey,
        },
    )
}

async fn insert(db: &Database, index: u64, script_pubkey: ScriptBuf) {
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&OutputKey(index), &output(script_pubkey))
        .await;
    dbtx.commit_tx().await;
}

#[tokio::test]
async fn await_outputs_continues_past_non_p2wsh_outputs() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let p2pkh = ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros());
    let p2wsh = ScriptBuf::new_p2wsh(&WScriptHash::all_zeros());

    insert(&db, 0, p2pkh.clone()).await;
    insert(&db, 1, p2pkh).await;
    insert(&db, 2, p2wsh.clone()).await;

    // A batch of only non-p2wsh outputs is empty but still advances.
    let (outputs, next) = await_outputs(db.clone(), 0, 2).await;
    assert!(outputs.is_empty());
    assert_eq!(next, 2);

    let (outputs, next) = await_outputs(db.clone(), next, 2).await;
    assert_eq!(outputs.iter().map(|o| o.index).collect::<Vec<_>>(), [2]);
    assert_eq!(next, 3);

    // A request at the head blocks until the output exists.
    let mut pending = pin!(await_outputs(db.clone(), next, 2));
    assert!(poll!(&mut pending).is_pending());
    insert(&db, 3, p2wsh).await;
    let (outputs, next) = pending.await;
    assert_eq!(outputs.iter().map(|o| o.index).collect::<Vec<_>>(), [3]);
    assert_eq!(next, 4);
}

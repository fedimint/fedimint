use criterion::{criterion_group, criterion_main, Criterion};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::rand::{thread_rng, Rng};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_rocksdb::RocksDb;
use futures::StreamExt;
use tokio::runtime::Runtime;

#[repr(u8)]
#[derive(Clone)]
enum TestDbKeyPrefix {
    Test = 254,
    MaxTest = 255,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
struct TestKey(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
struct TestVal(pub Vec<u8>);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefix;

impl_db_record!(
    key = TestKey,
    value = TestVal,
    db_prefix = TestDbKeyPrefix::Test,
    notify_on_modify = true,
);
impl_db_lookup!(key = TestKey, query_prefix = DbPrefixTestPrefix);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
struct TestKey2(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable)]
struct TestVal2(pub Vec<u8>);

#[derive(Debug, Encodable, Decodable)]
struct DbPrefixTestPrefixMax;

impl_db_record!(
    key = TestKey2,
    value = TestVal2,
    db_prefix = TestDbKeyPrefix::MaxTest, // max/last prefix
    notify_on_modify = true,
);
impl_db_lookup!(key = TestKey2, query_prefix = DbPrefixTestPrefixMax);

async fn new_db() -> Database {
    let path = tempfile::Builder::new()
        .prefix("rocksdb-bench")
        .tempdir()
        .expect("Failed to create temp dir");

    Database::new(
        RocksDb::open(&path).expect("Failed to open DB"),
        ModuleDecoderRegistry::default(),
    )
}

const ENTRIES: usize = 100000;

async fn fill_db(dbtx: &mut DatabaseTransaction<'_>) {
    let mut rng = thread_rng();
    for i in 0..ENTRIES {
        // Value is a vec with random bytes between 10 and 100 bytes long
        let length = rng.gen_range(10..=100);
        let mut value = vec![0; length];
        rng.fill(&mut value[..]);

        dbtx.insert_entry(&TestKey(i.to_be_bytes().to_vec()), &TestVal(value))
            .await;
    }

    dbtx.insert_entry(&TestKey2(vec![0]), &TestVal2(vec![3]))
        .await;
    dbtx.insert_entry(&TestKey2(vec![254]), &TestVal2(vec![1]))
        .await;
    dbtx.insert_entry(&TestKey2(vec![255]), &TestVal2(vec![2]))
        .await;
}

async fn reverse_prefix_search(db: &Database) {
    let mut dbtx = db.begin_transaction().await;
    let query = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    assert_eq!(query.len(), ENTRIES);
}

async fn reverse_prefix_search_only_first(db: &Database) {
    let mut dbtx = db.begin_transaction().await;
    let query = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
        .await
        .next()
        .await
        .expect("No entries found");
    assert_eq!(query.0 .0, (ENTRIES - 1).to_be_bytes().to_vec());
}

async fn prefix_search(db: &Database) {
    let mut dbtx = db.begin_transaction().await;
    let query = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .collect::<Vec<_>>()
        .await;
    assert_eq!(query.len(), ENTRIES);
}

async fn prefix_search_only_first(db: &Database) {
    let mut dbtx = db.begin_transaction().await;
    let query = dbtx
        .find_by_prefix(&DbPrefixTestPrefix)
        .await
        .next()
        .await
        .expect("No entries found");
    assert_eq!(query.0 .0, vec![0u8; 8]);
}

async fn increment_last(db: &Database) {
    let mut dbtx = db.begin_transaction().await;
    let query = dbtx
        .find_by_prefix_sorted_descending(&DbPrefixTestPrefix)
        .await
        .next()
        .await
        .expect("No entries found");
    let next = usize::from_be_bytes(query.0 .0.try_into().expect("Invalid DB entry")) + 1;

    dbtx.insert_entry(&TestKey(next.to_be_bytes().to_vec()), &TestVal(vec![0; 50]))
        .await;
    dbtx.commit_tx().await;
}

fn benchmark_reverse_retrieval(c: &mut Criterion) {
    let mut group = c.benchmark_group("async_group");

    let rt = Runtime::new().expect("Failed to create runtime");
    let db = rt.block_on(async {
        let db = new_db().await;
        let mut dbtx = db.begin_transaction().await;
        fill_db(&mut dbtx.to_ref_nc()).await;
        dbtx.commit_tx().await;
        db
    });

    group.bench_function("reverse_prefix_search_only_first", |b| {
        b.to_async(&rt)
            .iter(|| reverse_prefix_search_only_first(&db));
    });

    group.bench_function("reverse_prefix_search", |b| {
        b.to_async(&rt).iter(|| reverse_prefix_search(&db));
    });

    group.bench_function("prefix_search_only_first", |b| {
        b.to_async(&rt).iter(|| prefix_search_only_first(&db));
    });

    group.bench_function("prefix_search", |b| {
        b.to_async(&rt).iter(|| prefix_search(&db));
    });

    group.bench_function("increment_last", |b| {
        b.to_async(&rt).iter(|| increment_last(&db));
    });

    group.finish();
}

criterion_group!(benches, benchmark_reverse_retrieval);
criterion_main!(benches);

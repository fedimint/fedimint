use std::borrow::Cow;
use std::{fmt, ptr};

use futures::StreamExt;

use crate::core::{
    DecoderBuilder, DynModuleConsensusItem, IntoDynInstance, ModuleConsensusItem, ModuleInstanceId,
    ModuleKind,
};
use crate::db::mem_impl::MemDatabase;
use crate::db::{
    Committable, Database, DatabaseKeyPrefix, DatabaseTransaction, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped, WithDecoders,
};
use crate::encoding::{Decodable, Encodable};
use crate::module::registry::{DecodingMode, ModuleDecoderRegistry};
use crate::task::MaybeSend;
use crate::time::now;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable)]
struct TestItem(u64);

impl fmt::Display for TestItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ModuleConsensusItem for TestItem {
    const KIND: ModuleKind = ModuleKind::from_static_str("decoder-borrow-test");
}

impl IntoDynInstance for TestItem {
    type DynType = DynModuleConsensusItem;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynModuleConsensusItem::from_typed(instance_id, self)
    }
}

#[derive(Debug, Encodable, Decodable)]
struct ItemKey(u64);

#[derive(Debug, Encodable, Decodable)]
struct ItemPrefix;

crate::impl_db_record!(
    key = ItemKey,
    value = DynModuleConsensusItem,
    db_prefix = 0x42
);
crate::impl_db_lookup!(key = ItemKey, query_prefix = ItemPrefix);

fn registry(module_count: u16) -> ModuleDecoderRegistry {
    let mut builder = DecoderBuilder::default();
    builder.with_decodable_type::<TestItem>();
    let decoder = builder.build();
    (0..module_count)
        .map(|id| {
            (
                id,
                // Configuration-loaded kinds own their strings. Include those
                // outer-map allocations, not just static kinds, in the benchmark.
                ModuleKind::from(TestItem::KIND.as_str().to_owned()),
                decoder.clone(),
            )
        })
        .collect()
}

fn assert_borrowed<Cap>(tx: &DatabaseTransaction<'_, Cap>, original: *const ModuleDecoderRegistry) {
    assert!(matches!(tx.decoders, Cow::Borrowed(_)));
    assert!(ptr::eq(tx.decoders(), original));
}

#[tokio::test]
async fn every_reference_path_shares_parent_decoder_metadata() {
    for module_count in [0, 4, 16] {
        let db = Database::new(MemDatabase::new(), registry(module_count));
        let mut root = db.begin_transaction().await;
        assert!(matches!(root.decoders, Cow::Owned(_)));
        let original = ptr::from_ref(root.decoders());

        {
            let mut child = root.to_ref();
            assert_borrowed(&child, original);
            let mut nested = child.to_ref_nc();
            assert_borrowed(&nested, original);
            let moved = nested.to_ref().into_nc().with_prefix(vec![7]);
            assert_borrowed(&moved, original);
        }
        {
            let mut prefixed = root.to_ref_with_prefix(vec![8]);
            assert_borrowed(&prefixed, original);
            assert_borrowed(&prefixed.to_ref(), original);
        }
        {
            let (mut module, token) = root.to_ref_with_prefix_module_id(3);
            assert_borrowed(&module, original);
            let mut nested = module.to_ref_with_prefix(vec![9]);
            assert_borrowed(&nested, original);
            let mut global = nested.global_dbtx(token);
            assert!(global.is_global());
            assert_borrowed(&global, original);
            assert_borrowed(&global.to_ref_nc(), original);
        }
        {
            let (moved, _) = root.to_ref().with_prefix_module_id(2);
            assert_borrowed(&moved, original);
        }

        // Consuming transformations retain ownership when the input owns it.
        let root = root.into_nc().with_prefix(vec![10]);
        assert!(matches!(root.decoders, Cow::Owned(_)));
        let (root, _) = root.with_prefix_module_id(1);
        assert!(matches!(root.decoders, Cow::Owned(_)));
    }
}

#[tokio::test]
async fn nested_partitions_global_access_and_streams_keep_the_decoder_context() {
    let db = Database::new(MemDatabase::new(), registry(2));
    let global_value = TestItem(10).into_dyn(0);
    let module_value = TestItem(20).into_dyn(1);
    let other_value = TestItem(30).into_dyn(0);
    let nested_value = TestItem(40).into_dyn(1);
    let mut root = db.begin_transaction().await;
    root.insert_new_entry(&ItemKey(0), &global_value).await;

    {
        let (mut module, token) = root.to_ref_with_prefix_module_id(0);
        module.insert_new_entry(&ItemKey(0), &module_value).await;
        {
            let mut nested = module.to_ref_with_prefix(vec![8]);
            nested.insert_new_entry(&ItemKey(0), &nested_value).await;
            assert_eq!(nested.get_value(&ItemKey(0)).await, Some(nested_value));
            let mut global = nested.global_dbtx(token);
            assert_eq!(
                global.get_value(&ItemKey(0)).await,
                Some(global_value.clone())
            );
        }
        assert_eq!(
            module.get_value(&ItemKey(0)).await,
            Some(module_value.clone())
        );
        assert_eq!(
            module.raw_get_bytes(&ItemKey(0).to_bytes()).await.unwrap(),
            Some(module_value.consensus_encode_to_vec())
        );

        // Each typed stream still owns its decoder snapshot. Drop the stream
        // before reusing the borrowed transaction, then reuse its parent.
        let prefix_values = module
            .find_by_prefix(&ItemPrefix)
            .await
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(prefix_values, vec![module_value.clone()]);
        let descending_values = module
            .find_by_prefix_sorted_descending(&ItemPrefix)
            .await
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(descending_values, vec![module_value.clone()]);
        let range_values = module
            .find_by_range(ItemKey(0)..ItemKey(1))
            .await
            .map(|(_, value)| value)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(range_values, vec![module_value.clone()]);
    }
    root.to_ref_with_prefix_module_id(1)
        .0
        .insert_new_entry(&ItemKey(0), &other_value)
        .await;
    root.commit_tx().await;

    let mut root = db.begin_transaction_nc().await;
    assert_eq!(root.get_value(&ItemKey(0)).await, Some(global_value));
    assert_eq!(
        root.to_ref_with_prefix_module_id(0)
            .0
            .get_value(&ItemKey(0))
            .await,
        Some(module_value)
    );
    assert_eq!(
        root.to_ref_with_prefix_module_id(1)
            .0
            .get_value(&ItemKey(0))
            .await,
        Some(other_value)
    );
}

#[tokio::test]
async fn owning_roots_and_cloned_registries_keep_independent_modes_and_modules() {
    let original = registry(1);
    let mut independent = original.clone().with_fallback();
    independent.register_module(1, TestItem::KIND, registry(1).get_expect(0).clone());
    assert_eq!(original.decoding_mode(), DecodingMode::Reject);
    assert!(original.get(1).is_none());

    let db = Database::new(MemDatabase::new(), original);
    let fallback_db = db.with_decoders(independent.clone());
    let mut rejecting = db.begin_transaction_nc().await;
    let mut fallback = fallback_db.begin_transaction_nc().await;
    independent.register_module(2, TestItem::KIND, registry(1).get_expect(0).clone());
    for (_, _, decoder) in independent.iter_modules_mut() {
        *decoder = DecoderBuilder::default().build();
    }
    assert!(fallback.decoders().get(2).is_none());
    assert!(matches!(rejecting.decoders, Cow::Owned(_)));
    assert!(matches!(fallback.decoders, Cow::Owned(_)));
    assert!(!ptr::eq(rejecting.decoders(), fallback.decoders()));

    let rejecting = rejecting.to_ref();
    let fallback = fallback.to_ref_with_prefix(vec![7]);
    assert_eq!(rejecting.decoders().decoding_mode(), DecodingMode::Reject);
    assert_eq!(fallback.decoders().decoding_mode(), DecodingMode::Fallback);
    assert!(rejecting.decoders().get(1).is_none());
    assert!(fallback.decoders().get(1).is_some());
    let known = TestItem(42).into_dyn(0);
    for decoders in [rejecting.decoders(), fallback.decoders()] {
        assert_eq!(
            DynModuleConsensusItem::consensus_decode_whole(
                &known.consensus_encode_to_vec(),
                decoders
            )
            .unwrap(),
            known
        );
    }
    let unknown_bytes = TestItem(99).into_dyn(9).consensus_encode_to_vec();
    assert!(
        DynModuleConsensusItem::consensus_decode_whole(&unknown_bytes, rejecting.decoders())
            .is_err()
    );
    let unknown =
        DynModuleConsensusItem::consensus_decode_whole(&unknown_bytes, fallback.decoders())
            .unwrap();
    assert_eq!(unknown.consensus_encode_to_vec(), unknown_bytes);
}

#[test]
fn transaction_metadata_preserves_maybe_send() {
    fn assert_maybe_send<T: MaybeSend>() {}
    assert_maybe_send::<DatabaseTransaction<'static, Committable>>();
    assert_maybe_send::<DatabaseTransaction<'static>>();
}

/// A local comparison of metadata cloning, not backend throughput or RSS.
#[tokio::test]
#[ignore = "manual decoder metadata reborrow benchmark"]
async fn benchmark_reborrow_metadata() {
    use std::hint::black_box;

    eprintln!(
        "Metadata field sizes: registry={} bytes, Cow={} bytes",
        size_of::<ModuleDecoderRegistry>(),
        size_of::<Cow<'static, ModuleDecoderRegistry>>(),
    );
    let iterations = 100_000;
    for module_count in [0, 4, 16] {
        let db = Database::new(MemDatabase::new(), registry(module_count));
        let mut root = db.begin_transaction_nc().await;
        let start = now();
        for _ in 0..iterations {
            // Model the former extra metadata clone; keep the same transaction
            // adapter allocation in both paths. Decoder internals are already Arc.
            let cloned = black_box(root.decoders()).clone();
            let reference = root.to_ref();
            black_box(reference.decoders());
            black_box(reference);
            black_box(cloned);
        }
        let cloned_elapsed = now().duration_since(start).unwrap();
        let start = now();
        for _ in 0..iterations {
            let reference = root.to_ref();
            black_box(reference.decoders());
            black_box(reference);
        }
        let borrowed_elapsed = now().duration_since(start).unwrap();
        eprintln!(
            "{module_count} modules, {iterations} reborrows: \
             with metadata clone={cloned_elapsed:?}, borrowed={borrowed_elapsed:?}; \
             {iterations} outer registry clones removed, transaction boxes remain"
        );
    }
}

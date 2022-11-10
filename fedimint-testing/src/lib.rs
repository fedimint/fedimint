use std::collections::HashSet;
use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_api::config::GenerateConfig;
use fedimint_api::db::mem_impl::MemDatabase;
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::{ApiError, ModuleError, TransactionItemAmount};
use fedimint_api::InputMeta;
use fedimint_api::{FederationModule, OutPoint, PeerId};

pub mod bitcoind;

pub struct FakeFed<M, CC> {
    members: Vec<(PeerId, M, Database)>,
    client_cfg: CC,
    block_height: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestInputMeta {
    pub amount: TransactionItemAmount,
    pub keys: Vec<secp256k1_zkp::XOnlyPublicKey>,
}

impl<M, CC> FakeFed<M, CC>
where
    M: FederationModule,
    M::ConsensusItem: Clone,
    M::TxOutputOutcome: Eq + Debug,
{
    pub async fn new<C, F, FF>(
        members: usize,
        constructor: F,
        params: &C::Params,
    ) -> FakeFed<M, C::ClientConfig>
    where
        C: GenerateConfig,
        F: Fn(C, Database) -> FF, // TODO: put constructor into Module trait
        FF: Future<Output = M>,
    {
        let peers = (0..members)
            .map(|idx| PeerId::from(idx as u16))
            .collect::<Vec<_>>();
        let (server_cfg, client_cfg) = C::trusted_dealer_gen(&peers, params, rand::rngs::OsRng);

        let mut members = vec![];
        for (peer, cfg) in server_cfg {
            let mem_db: Database = MemDatabase::new().into();
            let member = constructor(cfg, mem_db.clone()).await;
            members.push((peer, member, mem_db));
        }

        FakeFed {
            members,
            client_cfg,
            block_height: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_block_height(&self, bh: u64) {
        self.block_height.store(bh, Ordering::Relaxed);
    }

    pub fn verify_input(&self, input: &M::TxInput) -> Result<TestInputMeta, ModuleError> {
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());

        let results = self.members.iter().map(|(_, member, _)| {
            let cache = member.build_verification_cache(std::iter::once(input));
            let InputMeta { amount, puk_keys } = member.validate_input(&fake_ic, &cache, input)?;
            Ok(TestInputMeta {
                amount,
                keys: puk_keys.collect(),
            })
        });
        assert_all_equal_result(results)
    }

    pub fn verify_output(&self, output: &M::TxOutput) -> bool {
        let results = self
            .members
            .iter()
            .map(|(_, member, _)| member.validate_output(output).is_err());
        assert_all_equal(results)
    }

    // TODO: add expected result to inputs/outputs
    pub async fn consensus_round(
        &mut self,
        inputs: &[M::TxInput],
        outputs: &[(OutPoint, M::TxOutput)],
    ) where
        <M as FederationModule>::TxInput: Send + Sync,
    {
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());

        // TODO: only include some of the proposals for realism
        let mut consensus = vec![];
        for (id, member, _db) in &mut self.members {
            consensus.extend(
                member
                    .consensus_proposal()
                    .await
                    .into_iter()
                    .map(|ci| (*id, ci)),
            );
        }

        let peers: HashSet<PeerId> = self.members.iter().map(|p| p.0).collect();
        for (_peer, member, db) in &mut self.members {
            let database = db as &mut Database;
            let mut dbtx = database.begin_transaction();

            member
                .begin_consensus_epoch(&mut dbtx, consensus.clone())
                .await;

            let cache = member.build_verification_cache(inputs.iter());
            for input in inputs {
                member
                    .apply_input(&fake_ic, &mut dbtx, input, &cache)
                    .expect("Faulty input");
            }

            for (out_point, output) in outputs {
                member
                    .apply_output(&mut dbtx, output, *out_point)
                    .expect("Faulty output");
            }

            dbtx.commit_tx().await.expect("DB Error");

            let mut dbtx = database.begin_transaction();
            member.end_consensus_epoch(&peers, &mut dbtx).await;

            dbtx.commit_tx().await.expect("DB Error");
        }
    }

    pub fn output_outcome(&self, out_point: OutPoint) -> Option<M::TxOutputOutcome> {
        // Since every member is in the same epoch they should have the same internal state, even
        // in terms of outcomes. This may change later once end_consensus_epoch is pulled out of the
        // main consensus loop into another thread to optimize latency. This test will probably fail
        // then.
        assert_all_equal(
            self.members
                .iter()
                .map(|(_, member, _)| member.output_status(out_point)),
        )
    }

    pub async fn patch_dbs<U>(&mut self, update: U)
    where
        U: Fn(&mut DatabaseTransaction),
    {
        for (_, _, db) in &mut self.members {
            let mut dbtx = db.begin_transaction();
            update(&mut dbtx);
            dbtx.commit_tx().await.expect("DB Error");
        }
    }

    pub fn client_cfg(&self) -> &CC {
        &self.client_cfg
    }

    pub fn fetch_from_all<O, F>(&mut self, fetch: F) -> O
    where
        O: Debug + Eq,
        F: Fn(&mut M) -> O,
    {
        assert_all_equal(self.members.iter_mut().map(|(_, member, _)| fetch(member)))
    }
}

fn assert_all_equal<I>(mut iter: I) -> I::Item
where
    I: Iterator,
    I::Item: Eq + Debug,
{
    let first = iter.next().expect("empty iterator");
    for item in iter {
        assert_eq!(first, item);
    }
    first
}

/// Make sure all elements are equal for `Result<O, E>`
///
/// For errors their conversion to `String` via `Debug` is used to avoid
/// `E : Eq`.
fn assert_all_equal_result<I, O, E>(mut iter: I) -> I::Item
where
    I: Iterator<Item = Result<O, E>>,
    O: Eq + Debug,
    E: Debug,
{
    let first = iter.next().expect("empty iterator");

    match &first {
        Ok(first) => {
            for item in iter {
                match item {
                    Ok(item) => {
                        assert_eq!(first, &item);
                    }
                    Err(e) => {
                        panic!("Assertion error: Ok({first:?}) != Err({e:?})");
                    }
                }
            }
        }
        Err(first) => {
            let first = format!("{first:?}");

            for item in iter {
                match item {
                    Ok(o) => {
                        panic!("Assertion error: Err({first}) != Ok({o:?})");
                    }
                    Err(e) => {
                        assert_eq!(first, format!("{e:?}"));
                    }
                }
            }
        }
    }

    first
}

struct FakeInterconnect(
    Box<
        dyn Fn(&'static str, String, serde_json::Value) -> Result<serde_json::Value, ApiError>
            + Sync
            + Send,
    >,
);

impl FakeInterconnect {
    fn new_block_height_responder(bh: Arc<AtomicU64>) -> FakeInterconnect {
        FakeInterconnect(Box::new(move |module, path, _data| {
            assert_eq!(module, "wallet");
            assert_eq!(path, "/block_height");

            let height = bh.load(Ordering::Relaxed);
            Ok(serde_json::to_value(height).expect("encoding error"))
        }))
    }
}

#[async_trait]
impl ModuleInterconect for FakeInterconnect {
    async fn call(
        &self,
        module: &'static str,
        path: String,
        data: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        (self.0)(module, path, data)
    }
}

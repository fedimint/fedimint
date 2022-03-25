use crate::config::GenerateConfig;
use crate::db::batch::DbBatch;
use crate::db::mem_impl::MemDatabase;
use crate::db::Database;
use crate::module::http;
use crate::module::interconnect::ModuleInterconect;
use crate::{Amount, FederationModule, InputMeta, OutPoint, PeerId};
use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct FakeFed<M, CC> {
    members: Vec<(PeerId, M, MemDatabase)>,
    client_cfg: CC,
    block_height: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TestInputMeta {
    pub amount: Amount,
    pub keys: Vec<secp256k1_zkp::schnorrsig::PublicKey>,
}

impl<M, CC> FakeFed<M, CC>
where
    M: FederationModule,
    M::ConsensusItem: Clone,
    M::Error: Debug + Eq,
    M::TxOutputOutcome: Eq + Debug,
{
    pub async fn new<C, F, FF>(
        members: usize,
        max_evil: usize,
        constructor: F,
        params: &C::Params,
    ) -> FakeFed<M, C::ClientConfig>
    where
        C: GenerateConfig,
        F: Fn(C, MemDatabase) -> FF, // TODO: put constructor into Module trait
        FF: Future<Output = M>,
    {
        let peers = (0..members)
            .map(|idx| PeerId::from(idx as u16))
            .collect::<Vec<_>>();
        let (server_cfg, client_cfg) =
            C::trusted_dealer_gen(&peers, max_evil, params, rand::rngs::OsRng::new().unwrap());

        let mut members = vec![];
        for (peer, cfg) in server_cfg {
            let mem_db = MemDatabase::new();
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

    pub fn verify_input(&self, input: &M::TxInput) -> Result<TestInputMeta, M::Error> {
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());

        let results = self.members.iter().map(|(_, member, _)| {
            let cache = member.build_verification_cache(std::iter::once(input));
            let InputMeta { amount, puk_keys } = member.validate_input(&fake_ic, &cache, input)?;
            Ok(TestInputMeta {
                amount,
                keys: puk_keys.collect(),
            })
        });
        assert_all_equal(results)
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
    ) {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());

        // TODO: only include some of the proposals for realism
        let mut consensus = vec![];
        for (id, member, _db) in &mut self.members {
            consensus.extend(
                member
                    .consensus_proposal(&mut rng)
                    .await
                    .into_iter()
                    .map(|ci| (*id, ci)),
            );
        }

        for (_peer, member, db) in &mut self.members {
            let mut batch = DbBatch::new();

            member
                .begin_consensus_epoch(batch.transaction(), consensus.clone(), &mut rng)
                .await;

            let cache = member.build_verification_cache(inputs.iter());
            for input in inputs {
                member
                    .apply_input(&fake_ic, batch.transaction(), input, &cache)
                    .expect("Faulty input");
            }

            for (out_point, output) in outputs {
                member
                    .apply_output(batch.transaction(), output, *out_point)
                    .expect("Faulty output");
            }

            (db as &mut dyn Database)
                .apply_batch(batch)
                .expect("DB error");

            let mut batch = DbBatch::new();
            member
                .end_consensus_epoch(batch.transaction(), &mut rng)
                .await;

            (db as &mut dyn Database)
                .apply_batch(batch)
                .expect("DB error");
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

    pub fn patch_dbs<U>(&mut self, update: U)
    where
        U: Fn(&mut dyn Database),
    {
        for (_, _, db) in &mut self.members {
            update(db);
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

struct FakeInterconnect(
    Box<
        dyn Fn(
            &'static str,
            String,
            http_types::Method,
            serde_json::Value,
        ) -> http_types::Result<http_types::Response>,
    >,
);

impl FakeInterconnect {
    fn new_block_height_responder(bh: Arc<AtomicU64>) -> FakeInterconnect {
        FakeInterconnect(Box::new(move |module, path, method, _data| {
            assert_eq!(module, "wallet");
            assert_eq!(path, "/block_height");
            assert_eq!(method, http::Method::Get);

            let height = bh.load(Ordering::Relaxed);
            Ok(http::Body::from_json(&height)
                .expect("Error encoding fake block height")
                .into())
        }))
    }
}

impl ModuleInterconect for FakeInterconnect {
    fn call(
        &self,
        module: &'static str,
        path: String,
        method: http::Method,
        data: serde_json::Value,
    ) -> http::Result<http::Response> {
        (self.0)(module, path, method, data)
    }
}

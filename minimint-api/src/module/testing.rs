use crate::config::GenerateConfig;
use crate::db::batch::DbBatch;
use crate::db::mem_impl::MemDatabase;
use crate::db::{Database, RawDatabase};
use crate::{Amount, FederationModule, InputMeta, OutPoint, PeerId};
use std::fmt::Debug;

pub struct FakeFed<M, CC> {
    members: Vec<(PeerId, M, MemDatabase)>,
    client_cfg: CC,
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
    pub fn new<C, F>(
        members: usize,
        max_evil: usize,
        constructor: F,
        params: &C::Params,
    ) -> FakeFed<M, C::ClientConfig>
    where
        C: GenerateConfig,
        F: Fn(C, MemDatabase) -> M, // TODO: put constructor into Module trait
    {
        let peers = (1..=members)
            .map(|idx| PeerId::from(idx as u16))
            .collect::<Vec<_>>();
        let (server_cfg, client_cfg) =
            C::trusted_dealer_gen(&peers, max_evil, params, rand::rngs::OsRng::new().unwrap());

        let members = server_cfg
            .into_iter()
            .map(|(peer, cfg)| {
                let mem_db = MemDatabase::new();
                let member = constructor(cfg, mem_db.clone());
                (peer, member, mem_db)
            })
            .collect();

        FakeFed {
            members,
            client_cfg,
        }
    }

    pub fn verify_input(&self, input: &M::TxInput) -> Result<TestInputMeta, M::Error> {
        let results = self.members.iter().map(|(_, member, _)| {
            let InputMeta { amount, puk_keys } = member.validate_input(input)?;
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

            for input in inputs {
                member
                    .apply_input(batch.transaction(), input)
                    .expect("Faulty input");
            }

            for (out_point, output) in outputs {
                member
                    .apply_output(batch.transaction(), output, *out_point)
                    .expect("Faulty output");
            }

            (db as &mut dyn RawDatabase)
                .apply_batch(batch)
                .expect("DB error");

            let mut batch = DbBatch::new();
            member
                .end_consensus_epoch(batch.transaction(), &mut rng)
                .await;

            (db as &mut dyn RawDatabase)
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
        U: Fn(&mut dyn RawDatabase),
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

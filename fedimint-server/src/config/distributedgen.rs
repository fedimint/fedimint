use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Write;

use anyhow::{ensure, format_err};
use async_trait::async_trait;
use bitcoin::secp256k1;
use bitcoin_hashes::sha256::{Hash as Sha256, HashEngine};
use fedimint_core::config::{DkgGroup, DkgMessage, DkgPeerMsg, DkgResult, ISupportedDkgMessage};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::PeerHandle;
use fedimint_core::net::peers::MuxPeerConnections;
use fedimint_core::task::spawn;
use fedimint_core::{BitcoinHash, NumPeers, PeerId};
use hbbft::crypto::poly::Commitment;
use hbbft::crypto::{G1Projective, G2Projective, PublicKeySet, SecretKeyShare};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tbs::hash::hash_bytes_to_curve;
use tbs::poly::Poly;
use tbs::Scalar;
use threshold_crypto::serde_impl::SerdeSecret;

struct Dkg<G> {
    gen_g: G,
    peers: Vec<PeerId>,
    our_id: PeerId,
    threshold: usize,
    f1_poly: Poly<Scalar, Scalar>,
    f2_poly: Poly<Scalar, Scalar>,
    hashed_commits: BTreeMap<PeerId, Sha256>,
    commitments: BTreeMap<PeerId, Vec<G>>,
    sk_shares: BTreeMap<PeerId, Scalar>,
    pk_shares: BTreeMap<PeerId, Vec<G>>,
}

/// Implementation of "Secure Distributed Key Generation for Discrete-Log Based
/// Cryptosystems" by Rosario Gennaro and Stanislaw Jarecki and Hugo Krawczyk
/// and Tal Rabin
///
/// Prevents any manipulation of the secret key, but fails with any
/// non-cooperative peers
impl<G: DkgGroup> Dkg<G> {
    /// Creates the DKG and the first step of the algorithm
    pub fn new(
        group: G,
        our_id: PeerId,
        peers: Vec<PeerId>,
        threshold: usize,
        rng: &mut impl rand::RngCore,
    ) -> (Self, DkgStep<G>) {
        let f1_poly: Poly<Scalar, Scalar> = Poly::random(threshold - 1, rng);
        let f2_poly: Poly<Scalar, Scalar> = Poly::random(threshold - 1, rng);

        let mut dkg = Dkg {
            gen_g: group,
            peers,
            our_id,
            threshold,
            f1_poly,
            f2_poly,
            hashed_commits: Default::default(),
            commitments: Default::default(),
            sk_shares: Default::default(),
            pk_shares: Default::default(),
        };

        // broadcast our commitment to the polynomials
        let commit: Vec<G> = dkg
            .f1_poly
            .coefficients()
            .map(|c| dkg.gen_g * *c)
            .zip(dkg.f2_poly.coefficients().map(|c| dkg.gen_h() * *c))
            .map(|(g, h)| g + h)
            .collect();

        let hashed = dkg.hash(commit.clone());
        dkg.commitments.insert(our_id, commit);
        dkg.hashed_commits.insert(our_id, hashed);
        let step = dkg.broadcast(DkgMessage::HashedCommit(hashed));

        (dkg, step)
    }

    /// Runs a single step of the DKG algorithm, processing a `msg` from `peer`
    pub fn step(&mut self, peer: PeerId, msg: DkgMessage<G>) -> anyhow::Result<DkgStep<G>> {
        match msg {
            DkgMessage::HashedCommit(hashed) => {
                match self.hashed_commits.get(&peer) {
                    Some(old) if *old != hashed => {
                        return Err(format_err!("{peer} sent us two hashes!"))
                    }
                    _ => self.hashed_commits.insert(peer, hashed),
                };

                if self.hashed_commits.len() == self.peers.len() {
                    let our_commit = self.commitments[&self.our_id].clone();
                    return Ok(self.broadcast(DkgMessage::Commit(our_commit)));
                }
            }
            DkgMessage::Commit(commit) => {
                let hash = self.hash(commit.clone());
                ensure!(self.threshold == commit.len(), "wrong degree from {peer}");
                ensure!(hash == self.hashed_commits[&peer], "wrong hash from {peer}");

                match self.commitments.get(&peer) {
                    Some(old) if *old != commit => {
                        return Err(format_err!("{peer} sent us two commitments!"))
                    }
                    _ => self.commitments.insert(peer, commit),
                };

                // once everyone has made commitments, send out shares
                if self.commitments.len() == self.peers.len() {
                    let mut messages = vec![];
                    for peer in &self.peers {
                        let s1 = self.f1_poly.evaluate(scalar(peer));
                        let s2 = self.f2_poly.evaluate(scalar(peer));

                        if *peer == self.our_id {
                            self.sk_shares.insert(self.our_id, s1);
                        } else {
                            messages.push((*peer, DkgMessage::Share(s1, s2)));
                        }
                    }
                    return Ok(DkgStep::Messages(messages));
                }
            }
            // Pedersen-VSS verifies the shares match the commitments
            DkgMessage::Share(s1, s2) => {
                let share_product = (self.gen_g * s1) + (self.gen_h() * s2);
                let commitment = self
                    .commitments
                    .get(&peer)
                    .ok_or_else(|| format_err!("{peer} sent share before commit"))?;
                let commit_product: G = commitment
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .reduce(|a, b| a + b)
                    .expect("sums");

                ensure!(share_product == commit_product, "bad commit from {peer}");
                match self.sk_shares.get(&peer) {
                    Some(old) if *old != s1 => {
                        return Err(format_err!("{peer} sent us two shares!"))
                    }
                    _ => self.sk_shares.insert(peer, s1),
                };

                if self.sk_shares.len() == self.peers.len() {
                    let extract: Vec<G> = self
                        .f1_poly
                        .coefficients()
                        .map(|c| self.gen_g * *c)
                        .collect();

                    self.pk_shares.insert(self.our_id, extract.clone());
                    return Ok(self.broadcast(DkgMessage::Extract(extract)));
                }
            }
            // Feldman-VSS exposes the public key shares
            DkgMessage::Extract(extract) => {
                let share = self
                    .sk_shares
                    .get(&peer)
                    .ok_or_else(|| format_err!("{peer} sent extract before share"))?;
                let share_product = self.gen_g * *share;
                let extract_product: G = extract
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| *commit * scalar(&self.our_id).pow(&[idx as u64, 0, 0, 0]))
                    .reduce(|a, b| a + b)
                    .expect("sums");

                ensure!(share_product == extract_product, "bad extract from {peer}");
                ensure!(self.threshold == extract.len(), "wrong degree from {peer}");
                match self.pk_shares.get(&peer) {
                    Some(old) if *old != extract => {
                        return Err(format_err!("{peer} sent us two extracts!"))
                    }
                    _ => self.pk_shares.insert(peer, extract),
                };

                if self.pk_shares.len() == self.peers.len() {
                    let sks = self.sk_shares.values().sum();

                    let pks: Vec<G> = (0..self.threshold)
                        .map(|idx| {
                            self.pk_shares
                                .values()
                                .map(|shares| *shares.get(idx).unwrap())
                                .reduce(|a, b| a + b)
                                .expect("sums")
                        })
                        .collect();

                    return Ok(DkgStep::Result(DkgKeys {
                        public_key_set: pks,
                        secret_key_share: sks,
                    }));
                }
            }
        }

        Ok(DkgStep::Messages(vec![]))
    }

    fn hash(&self, poly: Vec<G>) -> Sha256 {
        let mut engine = HashEngine::default();
        for element in poly.iter() {
            engine
                .write_all(element.to_bytes().as_ref())
                .expect("hashes");
        }
        Sha256::from_engine(engine)
    }

    fn broadcast(&self, msg: DkgMessage<G>) -> DkgStep<G> {
        let others = self.peers.iter().filter(|p| **p != self.our_id);
        DkgStep::Messages(others.map(|peer| (*peer, msg.clone())).collect())
    }

    /// Get a second generator by hashing the first one to the curve
    fn gen_h(&self) -> G {
        hash_bytes_to_curve::<G>(self.gen_g.clone().to_bytes().as_ref())
    }
}

/// PeerIds are offset by 1, since evaluating a poly at 0 reveals the secret
pub fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

pub struct DkgRunner<T> {
    peers: Vec<PeerId>,
    our_id: PeerId,
    dkg_config: HashMap<T, usize>,
}

/// Helper for running multiple DKGs over the same peer connections
///
/// Messages are `(T, DkgMessage)` for creating a DKG for every `T`
impl<T> DkgRunner<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash,
{
    /// Create multiple DKGs with the same `threshold` signatures required
    pub fn multi(keys: Vec<T>, threshold: usize, our_id: &PeerId, peers: &[PeerId]) -> Self {
        let dkg_config = keys.into_iter().map(|key| (key, threshold)).collect();

        Self {
            our_id: *our_id,
            peers: peers.to_vec(),
            dkg_config,
        }
    }

    /// Create a single DKG with `threshold` signatures required
    pub fn new(key: T, threshold: usize, our_id: &PeerId, peers: &[PeerId]) -> Self {
        Self::multi(vec![key], threshold, our_id, peers)
    }

    /// Create another DKG with `threshold` signatures required
    pub fn add(&mut self, key: T, threshold: usize) {
        self.dkg_config.insert(key, threshold);
    }

    /// Create keys from G2 (96B keys, 48B messages) used in `tbs`
    pub async fn run_g2(
        &mut self,
        module_id: ModuleInstanceId,
        connections: &MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
    ) -> DkgResult<HashMap<T, DkgKeys<G2Projective>>> {
        self.run(module_id, G2Projective::generator(), connections)
            .await
    }

    /// Create keys from G1 (48B keys, 96B messages) used in `threshold_crypto`
    pub async fn run_g1(
        &mut self,
        module_id: ModuleInstanceId,
        connections: &MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
    ) -> DkgResult<HashMap<T, DkgKeys<G1Projective>>> {
        self.run(module_id, G1Projective::generator(), connections)
            .await
    }

    /// Runs the DKG algorithms with our peers
    ///
    /// WARNING: Currently we do not handle any unexpected messages, all peers
    /// are expected to be cooperative
    pub async fn run<G: DkgGroup>(
        &mut self,
        module_id: ModuleInstanceId,
        group: G,
        connections: &MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
    ) -> DkgResult<HashMap<T, DkgKeys<G>>>
    where
        DkgMessage<G>: ISupportedDkgMessage,
    {
        // Use tokio channel to await on `recv` or we might block
        let (send, mut receive) = tokio::sync::mpsc::channel(10_000);

        // For every `key` we run DKG in a new tokio task
        self.dkg_config
            .clone()
            .into_iter()
            .for_each(|(key, threshold)| {
                let our_id = self.our_id;
                let peers = self.peers.clone();
                let connections = connections.clone();
                let key = serde_json::to_string(&key).expect("serialization can't fail");
                let send = send.clone();

                spawn("dkg runner", async move {
                    let (dkg, step) = Dkg::new(group, our_id, peers, threshold, &mut OsRng);
                    let result =
                        Self::run_dkg_key((module_id, key.clone()), connections, dkg, step).await;
                    send.send((key, result)).await.expect("channel open");
                });
            });

        // Collect every key, returning an error if any fails
        let mut results: HashMap<T, DkgKeys<G>> = HashMap::new();
        while results.len() < self.dkg_config.len() {
            let (key, result) = receive.recv().await.expect("channel open");
            let key = serde_json::from_str(&key).expect("serialization can't fail");
            results.insert(key, result?);
        }
        Ok(results)
    }

    /// Runs the DKG algorithms for a given key and module id
    async fn run_dkg_key<G: DkgGroup>(
        key_id: (ModuleInstanceId, String),
        connections: MuxPeerConnections<(ModuleInstanceId, String), DkgPeerMsg>,
        mut dkg: Dkg<G>,
        initial_step: DkgStep<G>,
    ) -> DkgResult<DkgKeys<G>>
    where
        DkgMessage<G>: ISupportedDkgMessage,
    {
        if let DkgStep::Messages(messages) = initial_step {
            for (peer, msg) in messages {
                let send_msg = DkgPeerMsg::DistributedGen(msg.to_msg());
                connections.send(&[peer], key_id.clone(), send_msg).await?;
            }
        }

        // process steps for each key
        loop {
            let (peer, msg) = connections.receive(key_id.clone()).await?;

            let message = match msg {
                DkgPeerMsg::DistributedGen(v) => Ok(v),
                _ => Err(format_err!(
                    "Key {key_id:?} wrong message received: {msg:?}"
                )),
            }?;

            let message = ISupportedDkgMessage::from_msg(message)?;
            let step = dkg.step(peer, message)?;

            match step {
                DkgStep::Messages(messages) => {
                    for (peer, msg) in messages {
                        let send_msg = DkgPeerMsg::DistributedGen(msg.to_msg());
                        connections.send(&[peer], key_id.clone(), send_msg).await?;
                    }
                }
                DkgStep::Result(result) => {
                    return Ok(result);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum DkgStep<G: DkgGroup> {
    Messages(Vec<(PeerId, DkgMessage<G>)>),
    Result(DkgKeys<G>),
}

#[derive(Debug, Clone)]
pub struct DkgKeys<G> {
    pub public_key_set: Vec<G>,
    pub secret_key_share: Scalar,
}

/// Our secret key share of a threshold key
#[derive(Debug, Clone)]
pub struct ThresholdKeys {
    pub public_key_set: PublicKeySet,
    pub secret_key_share: SerdeSecret<SecretKeyShare>,
}

impl DkgKeys<G2Projective> {
    pub fn tbs(self) -> (Poly<G2Projective, Scalar>, tbs::SecretKeyShare) {
        (
            Poly::from(self.public_key_set),
            tbs::SecretKeyShare(self.secret_key_share),
        )
    }
}

impl DkgKeys<G1Projective> {
    pub fn threshold_crypto(&self) -> ThresholdKeys {
        ThresholdKeys {
            public_key_set: PublicKeySet::from(Commitment::from(self.public_key_set.clone())),
            secret_key_share: SerdeSecret(SecretKeyShare::from_mut(
                &mut self.secret_key_share.clone(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use fedimint_core::PeerId;
    use hbbft::crypto::group::Curve;
    use hbbft::crypto::{G1Projective, G2Projective};
    use rand::rngs::OsRng;

    use crate::config::distributedgen::{scalar, Dkg, DkgGroup, DkgKeys, DkgStep, ThresholdKeys};

    #[test_log::test]
    fn test_dkg() {
        for (peer, keys) in run(G1Projective::generator()) {
            let ThresholdKeys {
                public_key_set,
                secret_key_share,
            } = keys.threshold_crypto();
            assert_eq!(public_key_set.threshold(), 2);
            assert_eq!(
                public_key_set.public_key_share(peer.to_usize()),
                secret_key_share.public_key_share()
            );
        }

        for (peer, keys) in run(G2Projective::generator()) {
            let (pk, sk) = keys.tbs();
            assert_eq!(pk.coefficients().len(), 3);
            assert_eq!(
                pk.evaluate(scalar(&peer)).to_affine(),
                sk.to_pub_key_share().0
            );
        }
    }

    fn run<G: DkgGroup>(group: G) -> HashMap<PeerId, DkgKeys<G>> {
        let mut rng = OsRng;
        let num_peers = 4;
        let threshold = 3;
        let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();

        let mut steps: VecDeque<(PeerId, DkgStep<G>)> = VecDeque::new();
        let mut dkgs: HashMap<PeerId, Dkg<G>> = HashMap::new();
        let mut keys: HashMap<PeerId, DkgKeys<G>> = HashMap::new();

        for peer in &peers {
            let (dkg, step) = Dkg::new(group, *peer, peers.clone(), threshold, &mut rng);
            dkgs.insert(*peer, dkg);
            steps.push_back((*peer, step));
        }

        while keys.len() < peers.len() {
            match steps.pop_front() {
                Some((peer, DkgStep::Messages(messages))) => {
                    for (receive_peer, msg) in messages {
                        let receive_dkg = dkgs.get_mut(&receive_peer).unwrap();
                        let step = receive_dkg.step(peer, msg);
                        steps.push_back((receive_peer, step.unwrap()));
                    }
                }
                Some((peer, DkgStep::Result(step_keys))) => {
                    keys.insert(peer, step_keys);
                }
                _ => {}
            }
        }

        keys
    }
}

// TODO: this trait is only needed to break the `DkgHandle` impl
// from it's definition that is still in `fedimint-core`
#[async_trait]
pub trait PeerHandleOps {
    async fn run_dkg_g1<T>(&self, v: T) -> DkgResult<HashMap<T, DkgKeys<G1Projective>>>
    where
        T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash + Sync;

    async fn run_dkg_multi_g2<T>(&self, v: Vec<T>) -> DkgResult<HashMap<T, DkgKeys<G2Projective>>>
    where
        T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash + Sync;

    async fn exchange_pubkeys(
        &self,
        dkg_key: String,
        key: secp256k1::PublicKey,
    ) -> DkgResult<BTreeMap<PeerId, secp256k1::PublicKey>>;
}

#[async_trait]
impl<'a> PeerHandleOps for PeerHandle<'a> {
    async fn run_dkg_g1<T>(&self, v: T) -> DkgResult<HashMap<T, DkgKeys<G1Projective>>>
    where
        T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash + Sync,
    {
        let mut dkg = DkgRunner::new(v, self.peers.threshold(), &self.our_id, &self.peers);
        dkg.run_g1(self.module_instance_id, self.connections).await
    }

    async fn run_dkg_multi_g2<T>(&self, v: Vec<T>) -> DkgResult<HashMap<T, DkgKeys<G2Projective>>>
    where
        T: Serialize + DeserializeOwned + Unpin + Send + Clone + Eq + Hash + Sync,
    {
        let mut dkg = DkgRunner::multi(v, self.peers.threshold(), &self.our_id, &self.peers);

        dkg.run_g2(self.module_instance_id, self.connections).await
    }

    async fn exchange_pubkeys(
        &self,
        dkg_key: String,
        key: secp256k1::PublicKey,
    ) -> DkgResult<BTreeMap<PeerId, secp256k1::PublicKey>> {
        let mut peer_peg_in_keys: BTreeMap<PeerId, secp256k1::PublicKey> = BTreeMap::new();

        self.connections
            .send(
                &self.peers,
                (self.module_instance_id, dkg_key.clone()),
                DkgPeerMsg::PublicKey(key),
            )
            .await?;

        peer_peg_in_keys.insert(self.our_id, key);
        while peer_peg_in_keys.len() < self.peers.len() {
            match self
                .connections
                .receive((self.module_instance_id, dkg_key.clone()))
                .await?
            {
                (peer, DkgPeerMsg::PublicKey(key)) => {
                    peer_peg_in_keys.insert(peer, key);
                }
                (peer, msg) => {
                    return Err(
                        format_err!("Invalid message received from: {peer}: {msg:?}").into(),
                    );
                }
            }
        }

        Ok(peer_peg_in_keys)
    }
}

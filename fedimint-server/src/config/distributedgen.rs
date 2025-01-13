use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Write;

use anyhow::{ensure, format_err, Context};
use async_trait::async_trait;
use bitcoin::hashes::sha256::{Hash as Sha256, HashEngine};
use bitcoin::hashes::Hash as BitcoinHash;
use bls12_381::Scalar;
use fedimint_core::config::{
    DkgError, DkgGroup, DkgMessage, DkgPeerMsg, DkgResult, ISupportedDkgMessage,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::PeerHandle;
use fedimint_core::net::peers::{DynP2PConnections, Recipient};
use fedimint_core::{NumPeers, PeerId};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha3::Digest;
use threshold_crypto::ff::Field;
use threshold_crypto::group::Curve;
use threshold_crypto::poly::Commitment;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{
    G1Affine, G1Projective, G2Affine, G2Projective, PublicKeySet, SecretKeyShare,
};

struct Dkg<G> {
    num_peers: NumPeers,
    identity: PeerId,
    generator: G,
    f1_poly: Vec<Scalar>,
    f2_poly: Vec<Scalar>,
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
    pub fn new(num_peers: NumPeers, identity: PeerId, generator: G) -> (Self, DkgStep<G>) {
        let f1_poly = random_scalar_coefficients(num_peers.threshold() - 1);
        let f2_poly = random_scalar_coefficients(num_peers.threshold() - 1);

        let mut dkg = Dkg {
            num_peers,
            identity,
            generator,
            f1_poly,
            f2_poly,
            hashed_commits: BTreeMap::new(),
            commitments: BTreeMap::new(),
            sk_shares: BTreeMap::new(),
            pk_shares: BTreeMap::new(),
        };

        // broadcast our commitment to the polynomials
        let commit: Vec<G> = dkg
            .f1_poly
            .iter()
            .map(|c| dkg.generator * *c)
            .zip(dkg.f2_poly.iter().map(|c| dkg.gen_h() * *c))
            .map(|(g, h)| g + h)
            .collect();

        let hashed = Dkg::hash(&commit);

        dkg.commitments.insert(identity, commit);
        dkg.hashed_commits.insert(identity, hashed);

        let step = dkg.broadcast(&DkgMessage::HashedCommit(hashed));

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

                if self.hashed_commits.len() == self.num_peers.total() {
                    let our_commit = self.commitments[&self.identity].clone();
                    return Ok(self.broadcast(&DkgMessage::Commit(our_commit)));
                }
            }
            DkgMessage::Commit(commit) => {
                let hash = Self::hash(&commit);
                ensure!(
                    self.num_peers.threshold() == commit.len(),
                    "wrong degree from {peer}"
                );
                ensure!(hash == self.hashed_commits[&peer], "wrong hash from {peer}");

                match self.commitments.get(&peer) {
                    Some(old) if *old != commit => {
                        return Err(format_err!("{peer} sent us two commitments!"))
                    }
                    _ => self.commitments.insert(peer, commit),
                };

                // once everyone has made commitments, send out shares
                if self.commitments.len() == self.num_peers.total() {
                    let mut messages = vec![];
                    for peer in self.num_peers.peer_ids() {
                        let s1 = evaluate_polynomial_scalar(&self.f1_poly, &scalar(&peer));
                        let s2 = evaluate_polynomial_scalar(&self.f2_poly, &scalar(&peer));

                        if peer == self.identity {
                            self.sk_shares.insert(self.identity, s1);
                        } else {
                            messages.push((peer, DkgMessage::Share(s1, s2)));
                        }
                    }
                    return Ok(DkgStep::Messages(messages));
                }
            }
            // Pedersen-VSS verifies the shares match the commitments
            DkgMessage::Share(s1, s2) => {
                let share_product = (self.generator * s1) + (self.gen_h() * s2);
                let commitment = self
                    .commitments
                    .get(&peer)
                    .ok_or_else(|| format_err!("{peer} sent share before commit"))?;
                let commit_product: G = commitment
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| {
                        *commit * scalar(&self.identity).pow(&[idx as u64, 0, 0, 0])
                    })
                    .reduce(|a, b| a + b)
                    .expect("sums");

                ensure!(share_product == commit_product, "bad commit from {peer}");
                match self.sk_shares.get(&peer) {
                    Some(old) if *old != s1 => {
                        return Err(format_err!("{peer} sent us two shares!"))
                    }
                    _ => self.sk_shares.insert(peer, s1),
                };

                if self.sk_shares.len() == self.num_peers.total() {
                    let extract: Vec<G> =
                        self.f1_poly.iter().map(|c| self.generator * *c).collect();

                    self.pk_shares.insert(self.identity, extract.clone());
                    return Ok(self.broadcast(&DkgMessage::Extract(extract)));
                }
            }
            // Feldman-VSS exposes the public key shares
            DkgMessage::Extract(extract) => {
                let share = self
                    .sk_shares
                    .get(&peer)
                    .ok_or_else(|| format_err!("{peer} sent extract before share"))?;
                let share_product = self.generator * *share;
                let extract_product: G = extract
                    .iter()
                    .enumerate()
                    .map(|(idx, commit)| {
                        *commit * scalar(&self.identity).pow(&[idx as u64, 0, 0, 0])
                    })
                    .reduce(|a, b| a + b)
                    .expect("sums");

                ensure!(share_product == extract_product, "bad extract from {peer}");
                ensure!(
                    self.num_peers.threshold() == extract.len(),
                    "wrong degree from {peer}"
                );
                match self.pk_shares.get(&peer) {
                    Some(old) if *old != extract => {
                        return Err(format_err!("{peer} sent us two extracts!"))
                    }
                    _ => self.pk_shares.insert(peer, extract),
                };

                if self.pk_shares.len() == self.num_peers.total() {
                    let sks = self.sk_shares.values().sum();

                    let pks: Vec<G> = (0..self.num_peers.threshold())
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

    fn hash(poly: &[G]) -> Sha256 {
        let mut engine = HashEngine::default();

        for element in poly {
            engine
                .write_all(element.to_bytes().as_ref())
                .expect("hashes");
        }

        Sha256::from_engine(engine)
    }

    fn broadcast(&self, message: &DkgMessage<G>) -> DkgStep<G> {
        DkgStep::Messages(
            self.num_peers
                .peer_ids()
                .filter(|peer| *peer != self.identity)
                .map(|peer| (peer, message.clone()))
                .collect(),
        )
    }

    /// Get a second generator by hashing the first one to the curve
    fn gen_h(&self) -> G {
        let mut hash_engine = sha3::Sha3_256::new();

        hash_engine.update(self.generator.clone().to_bytes().as_ref());

        G::random(&mut ChaChaRng::from_seed(hash_engine.finalize().into()))
    }
}

/// `PeerId`s are offset by 1, since evaluating a poly at 0 reveals the secret
pub fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}

/// Runs the DKG algorithms with our peers. We do not handle any unexpected
/// messages and all peers are expected to be cooperative.
pub async fn run_dkg<G: DkgGroup>(
    num_peers: NumPeers,
    identity: PeerId,
    generator: G,
    connections: &DynP2PConnections<DkgPeerMsg>,
) -> DkgResult<DkgKeys<G>>
where
    DkgMessage<G>: ISupportedDkgMessage,
{
    let (mut dkg, initial_step) = Dkg::new(num_peers, identity, generator);

    if let DkgStep::Messages(messages) = initial_step {
        for (peer, message) in messages {
            connections
                .send(
                    Recipient::Peer(peer),
                    DkgPeerMsg::DistributedGen(message.to_msg()),
                )
                .await;
        }
    }

    loop {
        for peer in num_peers.peer_ids().filter(|p| *p != identity) {
            let message = connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            let message = match message {
                DkgPeerMsg::DistributedGen(v) => Ok(v),
                _ => Err(format_err!("Wrong message received: {message:?}")),
            }?;

            match dkg.step(peer, ISupportedDkgMessage::from_msg(message)?)? {
                DkgStep::Messages(messages) => {
                    for (peer, message) in messages {
                        connections
                            .send(
                                Recipient::Peer(peer),
                                DkgPeerMsg::DistributedGen(message.to_msg()),
                            )
                            .await;
                    }
                }
                DkgStep::Result(result) => {
                    return Ok(result);
                }
            }
        }
    }
}

pub fn random_scalar_coefficients(degree: usize) -> Vec<Scalar> {
    (0..=degree).map(|_| Scalar::random(&mut OsRng)).collect()
}

pub fn evaluate_polynomial_scalar(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
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
    pub fn tbs(self) -> (Vec<G2Projective>, tbs::SecretKeyShare) {
        (
            self.public_key_set,
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

    pub fn tpe(self) -> (Vec<G1Projective>, Scalar) {
        (self.public_key_set, self.secret_key_share)
    }
}

pub fn evaluate_polynomial_g1(coefficients: &[G1Projective], x: &Scalar) -> G1Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

pub fn evaluate_polynomial_g2(coefficients: &[G2Projective], x: &Scalar) -> G2Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

// TODO: this trait is only needed to break the `DkgHandle` impl
// from it's definition that is still in `fedimint-core`
#[async_trait]
pub trait PeerHandleOps {
    async fn run_dkg_g1(&self) -> DkgResult<DkgKeys<G1Projective>>;

    async fn run_dkg_g2(&self) -> DkgResult<DkgKeys<G2Projective>>;

    /// Exchanges a `DkgPeerMsg::Module(Vec<u8>)` with all peers. All peers are
    /// required to be online and submit a response for this to return
    /// properly. The caller's message will be included in the returned
    /// `BTreeMap` under the `PeerId` of this peer. This allows modules to
    /// exchange arbitrary data during distributed key generation.
    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> DkgResult<BTreeMap<PeerId, T>>;
}

#[async_trait]
impl<'a> PeerHandleOps for PeerHandle<'a> {
    async fn run_dkg_g1(&self) -> DkgResult<DkgKeys<G1Projective>> {
        run_dkg(
            self.num_peers,
            self.identity,
            G1Projective::generator(),
            self.connections,
        )
        .await
    }

    async fn run_dkg_g2(&self) -> DkgResult<DkgKeys<G2Projective>> {
        run_dkg(
            self.num_peers,
            self.identity,
            G2Projective::generator(),
            self.connections,
        )
        .await
    }

    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> DkgResult<BTreeMap<PeerId, T>> {
        let mut peer_data: BTreeMap<PeerId, T> = BTreeMap::new();

        self.connections
            .send(
                Recipient::Everyone,
                DkgPeerMsg::Encodable(data.consensus_encode_to_vec()),
            )
            .await;

        peer_data.insert(self.identity, data);

        for peer in self.num_peers.peer_ids().filter(|p| *p != self.identity) {
            let message = self
                .connections
                .receive_from_peer(peer)
                .await
                .context("Unexpected shutdown of p2p connections")?;

            match message {
                DkgPeerMsg::Encodable(bytes) => {
                    let data = T::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                        .map_err(DkgError::ModuleDecodeError)?;

                    peer_data.insert(peer, data);
                }
                message => {
                    return Err(DkgError::Failed(anyhow::anyhow!(
                        "Invalid message from {peer}: {message:?}"
                    )));
                }
            }
        }

        Ok(peer_data)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use fedimint_core::{NumPeersExt, PeerId};
    use tbs::derive_pk_share;
    use threshold_crypto::{G1Projective, G2Projective};

    use crate::config::distributedgen::{
        evaluate_polynomial_g2, scalar, Dkg, DkgGroup, DkgKeys, DkgStep, ThresholdKeys,
    };

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
            assert_eq!(pk.len(), 3);
            assert_eq!(
                evaluate_polynomial_g2(&pk, &scalar(&peer)),
                derive_pk_share(&sk).0
            );
        }
    }

    fn run<G: DkgGroup>(group: G) -> HashMap<PeerId, DkgKeys<G>> {
        let peers = (0..4_u16).map(PeerId::from).collect::<Vec<_>>();

        let mut steps: VecDeque<(PeerId, DkgStep<G>)> = VecDeque::new();
        let mut dkgs: HashMap<PeerId, Dkg<G>> = HashMap::new();
        let mut keys: HashMap<PeerId, DkgKeys<G>> = HashMap::new();

        for peer in &peers {
            let (dkg, step) = Dkg::new(peers.to_num_peers(), *peer, group);
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

        assert!(steps.is_empty());

        keys
    }
}

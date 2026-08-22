use std::collections::BTreeMap;

use async_trait::async_trait;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{NumPeers, PeerId};
use group::Curve;

pub fn g1(scalar: &Scalar) -> G1Projective {
    G1Projective::generator() * scalar
}

pub fn g2(scalar: &Scalar) -> G2Projective {
    G2Projective::generator() * scalar
}

// Offset by 1, since evaluating a poly at 0 reveals the secret
pub fn scalar(peer: &PeerId) -> Scalar {
    Scalar::from(peer.to_usize() as u64 + 1)
}
pub fn eval_poly_g1(coefficients: &[G1Projective], peer: &PeerId) -> G1Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * scalar(peer) + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

pub fn eval_poly_g2(coefficients: &[G2Projective], peer: &PeerId) -> G2Affine {
    coefficients
        .iter()
        .copied()
        .rev()
        .reduce(|acc, coefficient| acc * scalar(peer) + coefficient)
        .expect("We have at least one coefficient")
        .to_affine()
}

// TODO: this trait is only needed to break the `DkgHandle` impl
// from it's definition that is still in `fedimint-core`
#[async_trait]
pub trait PeerHandleOps {
    fn num_peers(&self) -> NumPeers;

    fn identity(&self) -> PeerId;

    async fn run_dkg_g1(&self) -> anyhow::Result<(Vec<G1Projective>, Scalar)>;

    async fn run_dkg_g2(&self) -> anyhow::Result<(Vec<G2Projective>, Scalar)>;

    /// Exchanges a `DkgPeerMsg::Module(Vec<u8>)` with all peers. All peers are
    /// required to be online and submit a response for this to return
    /// properly. The caller's message will be included in the returned
    /// `BTreeMap` under the `PeerId` of this peer. This allows modules to
    /// exchange arbitrary data during distributed key generation.
    async fn exchange_bytes(&self, data: Vec<u8>) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>>;

    /// Sends a different `Vec<u8>` privately to each peer and returns
    /// what each peer sent us. `data` must contain an entry for every
    /// peer other than `self.identity()` and must not contain an entry
    /// for self. The returned map is keyed by sender and does not
    /// include an entry for self.
    async fn exchange_directed(
        &self,
        data: BTreeMap<PeerId, Vec<u8>>,
    ) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>>;
}

#[async_trait]
pub trait PeerHandleOpsExt {
    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> anyhow::Result<BTreeMap<PeerId, T>>;

    async fn exchange_directed_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: BTreeMap<PeerId, T>,
    ) -> anyhow::Result<BTreeMap<PeerId, T>>;
}

#[async_trait]
impl<O> PeerHandleOpsExt for O
where
    O: PeerHandleOps + Send + Sync + ?Sized,
{
    async fn exchange_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: T,
    ) -> anyhow::Result<BTreeMap<PeerId, T>> {
        let mut decoded = BTreeMap::new();
        for (k, bytes) in self.exchange_bytes(data.consensus_encode_to_vec()).await? {
            decoded.insert(
                k,
                T::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())?,
            );
        }
        Ok(decoded)
    }

    async fn exchange_directed_encodable<T: Encodable + Decodable + Send + Sync>(
        &self,
        data: BTreeMap<PeerId, T>,
    ) -> anyhow::Result<BTreeMap<PeerId, T>> {
        let encoded: BTreeMap<PeerId, Vec<u8>> = data
            .into_iter()
            .map(|(peer, value)| (peer, value.consensus_encode_to_vec()))
            .collect();

        let mut decoded = BTreeMap::new();
        for (k, bytes) in self.exchange_directed(encoded).await? {
            decoded.insert(
                k,
                T::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())?,
            );
        }
        Ok(decoded)
    }
}

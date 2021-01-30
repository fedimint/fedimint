use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use tbs::{
    combine_shares, sign_blinded_msg, Aggregatable, AggregatePublicKey, BlindedMessage,
    BlindedSignature, BlindedSignatureShare, Message, PublicKeyShare, SecretKeyShare, Signature,
};

#[derive(Debug)]
pub struct Mint {
    sec_key: SecretKeyShare,
    pub_key_shares: Vec<PublicKeyShare>,
    pub_key: AggregatePublicKey,
    threshold: usize,
    spendbook: HashSet<Message>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SignRequest(Vec<BlindedMessage>);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct PartialSigResponse(Vec<(BlindedMessage, BlindedSignatureShare)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SigResponse(Vec<(BlindedMessage, BlindedSignature)>);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Coin(Message, Signature);

impl Mint {
    pub fn new(sec_key: SecretKeyShare, pub_keys: Vec<PublicKeyShare>, threshold: usize) -> Mint {
        let pub_key = pub_keys.aggregate(threshold);
        Mint {
            sec_key,
            pub_key_shares: pub_keys,
            pub_key,
            threshold,
            spendbook: HashSet::new(),
        }
    }

    pub fn sign(&self, req: SignRequest) -> PartialSigResponse {
        PartialSigResponse(
            req.0
                .into_iter()
                .map(|msg| {
                    let bsig = sign_blinded_msg(msg, self.sec_key);
                    (msg, bsig)
                })
                .collect(),
        )
    }

    pub fn combine(&self, partial_sig: &[(u16, PartialSigResponse)]) -> Option<SigResponse> {
        let len = partial_sig.first()?.1 .0.len();
        assert!(partial_sig.iter().all(|s| s.1 .0.len() == len));
        let req_id = partial_sig.first().unwrap().1.id();

        let mut bsigs = vec![];
        for idx in 0..len {
            let comp_msg = partial_sig.first().unwrap().1 .0[idx].0;
            let sigs = self
                .pub_key_shares
                .iter()
                .enumerate()
                .map(|(peer_id, _)| {
                    let msg_sig = partial_sig
                        .iter()
                        .find(|(peer, _)| *peer as usize == peer_id)
                        .map(|(_, sig)| sig.0[idx]);

                    if let Some((msg, sig)) = msg_sig {
                        assert_eq!(comp_msg, msg);
                        Some(sig)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            let bsig = combine_shares(comp_msg, &sigs, &self.pub_key_shares, self.threshold);
            bsigs.push((comp_msg, bsig));
        }

        Some(SigResponse(bsigs))
    }

    pub fn spend(&mut self, coins: Vec<Coin>) -> bool {
        coins.into_iter().all(|c| self.spendbook.insert(c.0))
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

pub trait RequestId {
    fn id(&self) -> u64;
}

impl RequestId for SignRequest {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for PartialSigResponse {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0
            .iter()
            .map(|(msg, _)| msg)
            .collect::<Vec<_>>()
            .hash(&mut hasher);
        hasher.finish()
    }
}

impl RequestId for SigResponse {
    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0
            .iter()
            .map(|(msg, _)| msg)
            .collect::<Vec<_>>()
            .hash(&mut hasher);
        hasher.finish()
    }
}

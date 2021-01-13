use blindsign::keypair::BlindKeypair;
use blindsign::request::BlindRequest;
use blindsign::session::BlindSession;
use blindsign::signature::UnblindedSigData;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashSet;

type BSPublicKey = RistrettoPoint;
type BSSecretKey = Scalar;
type Nonce = [u8; 32];
type BlindedNonce = [u8; 32];
type SessionId = u64;
type SpendRequest = Vec<Coin>;
type InitiateIssuanceRequest = usize;

struct Mint {
    spend_book: HashSet<Nonce>,
    sec_key: BSSecretKey,
    federation_pub_key: Vec<BSPublicKey>,
    sessions: BTreeMap<SessionId, Vec<BlindSession>>,
    threshold: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct Coin {
    nonce: Nonce,
    signature: ThresholdSignature,
}

struct IssuanceRequest {
    session: SessionId,
    blinded_nonces: Vec<BlindedNonce>,
}

struct CoinSignRequest(BlindedNonce);

#[derive(Clone, Serialize, Deserialize)]
struct ThresholdSignature(Vec<Option<UnblindedSigData>>);

struct BlindSignSession {
    id: SessionId,
    rps: Vec<[u8; 32]>,
}

impl Mint {
    pub fn new(secret_key: BSSecretKey, public_keys: Vec<BSPublicKey>, threshold: usize) -> Self {
        Mint {
            spend_book: Default::default(),
            sec_key: secret_key,
            federation_pub_key: public_keys,
            sessions: Default::default(),
            threshold,
        }
    }

    fn begin_sign_session(&mut self, num_coins: usize) -> BlindSignSession {
        let session_id: u64 = thread_rng().gen();
        let (rps, sessions): (Vec<_>, Vec<_>) =
            (0..num_coins).map(|_| BlindSession::new().unwrap()).unzip();

        self.sessions.insert(session_id, sessions);

        BlindSignSession {
            id: session_id,
            rps,
        }
    }

    fn sign(&mut self, request: IssuanceRequest) -> Result<Vec<[u8; 32]>, MintError> {
        let session = self
            .sessions
            .remove(&request.session)
            .ok_or(MintError::UnknownSession)?;

        if session.len() != request.blinded_nonces.len() {
            return Err(MintError::WrongSingRequestLength);
        }

        Ok(session
            .into_iter()
            .zip(request.blinded_nonces)
            .map(|(session, req)| session.sign_ep(&req, self.sec_key).unwrap())
            .collect())
    }

    fn validate_signature(
        &self,
        signature: &[Option<UnblindedSigData>],
        msg: Nonce,
    ) -> Result<(), MintError> {
        if signature.len() != self.federation_pub_key.len() {
            return Err(MintError::InvalidSignatureLen);
        }

        if signature.iter().filter(|s| s.is_some()).count() < self.threshold {
            return Err(MintError::TooFewSignatures);
        }

        signature
            .iter()
            .zip(self.federation_pub_key.iter())
            .map(|(sig, pubkey)| {
                if let Some(sig) = sig.as_ref() {
                    if sig.msg_const_authenticate::<sha3::Sha3_512, _>(*pubkey, msg) {
                        Ok(())
                    } else {
                        Err(MintError::InvalidSignature)
                    }
                } else {
                    Ok(())
                }
            })
            .collect()
    }

    fn spend(&mut self, coins: Vec<Coin>) -> Result<(), MintError> {
        coins
            .into_iter()
            .map(|coin| {
                if !self.spend_book.insert(coin.nonce) {
                    return Err(MintError::DoubleSpend);
                };

                self.validate_signature(&coin.signature.0, coin.nonce)
            })
            .collect()
    }
}

struct IssuanceSession {
    nonces: Vec<Nonce>,
    sessions: BTreeMap<u16, (SessionId, Vec<BlindRequest>)>,
}

impl IssuanceSession {
    fn new(
        server_sessions: BTreeMap<u16, BlindSignSession>,
    ) -> (Self, BTreeMap<u16, IssuanceRequest>) {
        let nonces: Vec<[u8; 32]> = (0..server_sessions.get(&0).unwrap().rps.len())
            .map(|_| thread_rng().gen())
            .collect();

        let (sessions, requests): (
            BTreeMap<u16, (SessionId, Vec<BlindRequest>)>,
            BTreeMap<u16, IssuanceRequest>,
        ) = server_sessions
            .into_iter()
            .map(|(mint, session)| {
                let session_id = session.id;
                let (session, blinded_nonces): (Vec<_>, Vec<_>) = session
                    .rps
                    .into_iter()
                    .zip(nonces.iter())
                    .map(|(rp, nonce)| {
                        let (ep, br) =
                            BlindRequest::new_specific_msg::<sha3::Sha3_512, _>(&rp, nonce)
                                .unwrap();
                        (br, ep)
                    })
                    .unzip();
                let request = IssuanceRequest {
                    session: session_id,
                    blinded_nonces,
                };

                ((mint, (session_id, session)), (mint, request))
            })
            .unzip();

        (IssuanceSession { nonces, sessions }, requests)
    }

    fn finalize(self, blind_sigs: BTreeMap<u16, Vec<[u8; 32]>>) -> Result<Vec<Coin>, MintError> {
        let coin_count = self.sessions.get(&0).unwrap().1.len();
        if blind_sigs.values().any(|res| res.len() != coin_count) {
            return Err(MintError::WrongResponse);
        }

        let mut coins = Vec::with_capacity(coin_count);
        for coin_idx in 0..coin_count {
            let sig = self
                .sessions
                .iter()
                .map(|(mint_id, (_, brs))| {
                    if let Some(mint_response) = blind_sigs.get(mint_id) {
                        let sp = mint_response.get(coin_idx).unwrap();
                        let br = brs.get(coin_idx).unwrap();

                        Some((*br).clone().gen_signed_msg(sp).unwrap())
                    } else {
                        None
                    }
                })
                .collect();
            let nonce = self.nonces.get(coin_idx).unwrap();

            coins.push(Coin {
                nonce: *nonce,
                signature: ThresholdSignature(sig),
            });
        }

        Ok(coins)
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum MintError {
    UnknownSession,
    WrongSingRequestLength,
    DoubleSpend,
    InvalidSignature,
    InvalidSignatureLen,
    TooFewSignatures,
    WrongResponse,
}

#[cfg(test)]
mod tests {
    use crate::mint::{IssuanceSession, Mint, MintError};
    use blindsign::keypair::BlindKeypair;
    use std::collections::BTreeMap;

    #[test]
    fn test_issuance_happy_path() {
        let (sec_keys, pub_keys): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let keypair = BlindKeypair::generate().unwrap();
                (keypair.private(), keypair.public())
            })
            .unzip();

        let mut mints = sec_keys
            .into_iter()
            .map(|sk| Mint::new(sk, pub_keys.clone(), 4))
            .collect::<Vec<_>>();

        // Server starts sessions
        let server_responses = mints
            .iter_mut()
            .enumerate()
            .map(|(id, mint)| (id as u16, mint.begin_sign_session(100)))
            .collect::<BTreeMap<_, _>>();

        // Client blinds tokens
        let (session, next_step) = IssuanceSession::new(server_responses);

        // Server signs blinded tokens
        let server_responses = mints
            .iter_mut()
            .zip(next_step)
            .map(|(mint, (id, req))| (id as u16, mint.sign(req).unwrap()))
            .collect::<BTreeMap<_, _>>();

        // Unblind the tokens
        let coins = session.finalize(server_responses).unwrap();

        // Try spending the coins
        let some_mint = &mut mints[0];
        let (spend1, spend2) = coins.split_at(5);
        some_mint.spend(spend1.to_vec()).unwrap();
        some_mint.spend(spend2.to_vec()).unwrap();

        // Try double spend
        let spend3 = vec![spend1[0].clone()];
        assert_eq!(some_mint.spend(spend3), Err(MintError::DoubleSpend));
    }
}

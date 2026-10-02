use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_core::config::FederationId;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::{Keypair, Secp256k1};
use fedimint_core::task::spawn;
use frost_secp256k1_tr::round1::commit as Round1Commit;
use frost_secp256k1_tr::round2::sign as Round2Sign;
use frost_secp256k1_tr::{Identifier, Signature, SigningPackage, aggregate};
use iroh::{Endpoint, NodeAddr, RelayMode, SecretKey};
use rand::rngs::OsRng;

use crate::frost::dkg::{DkgResult, DkgRunner};
use crate::frost::session::{FrostDkgSessionRecord, FrostParticipant, SessionId};
use crate::frost::transport::file::FileTransport;
use crate::frost::transport::iroh::{DKG_ALPN, IrohDkgTransport};

fn dummy_federation_id() -> FederationId {
    FederationId::dummy()
}

fn create_frost_participant(n: usize) -> Vec<FrostParticipant> {
    let secp = Secp256k1::new();
    (0..n)
        .map(|_| {
            let kp = Keypair::new(&secp, &mut OsRng);
            FrostParticipant::from_pubkey(kp.public_key()).expect("invalid identifier")
        })
        .collect()
}

struct IrohNet {
    endpoints: Vec<Endpoint>,
    peers: BTreeMap<Identifier, NodeAddr>,
}

impl IrohNet {
    fn transport(&self, i: usize, session_id: SessionId) -> IrohDkgTransport {
        IrohDkgTransport::from_endpoint(self.endpoints[i].clone(), session_id, self.peers.clone())
    }
}

struct Consortium {
    participants: Vec<FrostParticipant>,
    session_id: SessionId,
    sessions: Vec<(Database, FrostDkgSessionRecord)>,
}

impl Consortium {
    async fn new(n: usize) -> anyhow::Result<Self> {
        let federation_id = dummy_federation_id();

        let participants: Vec<FrostParticipant> = create_frost_participant(n);

        let mut sessions = Vec::with_capacity(n);

        for participant in &participants {
            let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

            let record = FrostDkgSessionRecord::new(
                participant.clone(),
                participants.clone(),
                federation_id,
                &db,
            )
            .await?;

            sessions.push((db, record));
        }

        let session_id = sessions[0].1.session_id;

        Ok(Self {
            participants,
            session_id,
            sessions,
        })
    }

    async fn run(self) -> Vec<DkgResult> {
        let mut handles = Vec::with_capacity(self.sessions.len());

        for (db, record) in self.sessions {
            let session_id = self.session_id;

            handles.push(spawn("file_transport_dkg", async move {
                let transport = FileTransport::new(&session_id)
                    .await
                    .expect("transport init");

                record.run(&db, transport).await.expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }

    async fn iroh_net(&self) -> IrohNet {
        let mut endpoints = Vec::new();
        let mut peers = BTreeMap::new();

        for participant in &self.participants {
            let endpoint = Endpoint::builder()
                .secret_key(SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
                .alpns(vec![DKG_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .expect("bind endpoint");

            peers.insert(
                participant.identifier,
                endpoint.node_addr().await.expect("node addr"),
            );
            endpoints.push(endpoint);
        }

        IrohNet { endpoints, peers }
    }

    async fn run_iroh(self) -> Vec<DkgResult> {
        let net = self.iroh_net().await;
        let mut handles = Vec::with_capacity(self.sessions.len());

        for (i, (db, record)) in self.sessions.into_iter().enumerate() {
            let transport = net.transport(i, self.session_id);

            handles.push(spawn("iroh_transport_dkg", async move {
                sleep(Duration::from_millis(200 * i as u64)).await;
                record.run(&db, transport).await.expect("dkg failed")
            }));
        }

        let mut results = Vec::with_capacity(handles.len());

        for handle in handles {
            results.push(handle.await.expect("task panicked"));
        }

        results
    }
}

fn sign(signers: &[&DkgResult], msg: &[u8]) -> Result<Signature, frost_secp256k1_tr::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for s in signers {
        let id = *s.key_package.identifier();
        let (n, c) = Round1Commit(s.key_package.signing_share(), &mut OsRng);
        nonces.insert(id, n);
        commitments.insert(id, c);
    }

    let signing_package = SigningPackage::new(commitments, msg);

    let mut shares = BTreeMap::new();
    for s in signers {
        let id = *s.key_package.identifier();
        let share = Round2Sign(&signing_package, &nonces[&id], &s.key_package)?;
        shares.insert(id, share);
    }

    aggregate(&signing_package, &shares, &signers[0].pubkey_package)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_converges_to_same_aggregate_key() {
    let consortium = Consortium::new(3).await.expect("consortium failed");
    let results = consortium.run().await;
    let first = results[0].pubkey_package.verifying_key().serialize();

    for result in &results[1..] {
        assert_eq!(
            result.pubkey_package.verifying_key().serialize(),
            first,
            "all participants must converge on the same aggregate public key"
        );
    }
    for r in &results {
        let id = *r.key_package.identifier();
        assert_eq!(
            r.key_package.verifying_share(),
            r.pubkey_package.verifying_shares().get(&id).unwrap()
        );
    }
}

#[tokio::test]
async fn test_participants_have_unique_identifiers() {
    let consortium = Consortium::new(5).await.expect("consortium failed");

    let mut identifiers = std::collections::HashSet::new();

    for participant in &consortium.participants {
        assert!(
            identifiers.insert(participant.identifier),
            "participants must have unique identifiers"
        );
    }
}

#[tokio::test]
async fn test_all_participants_have_same_session_id() {
    let consortium = Consortium::new(5).await.expect("consortium failed");

    for (_, session) in &consortium.sessions {
        assert_eq!(
            session.session_id, consortium.session_id,
            "all participants must use the same DKG session ID"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_for_multiple_sizes() {
    for n in [2, 3, 4, 5, 7] {
        let consortium = Consortium::new(n).await;

        if n == 2 {
            assert!(
                consortium.is_err(),
                "DKG setup should fail for {n} participants"
            );
            continue;
        }

        let consortium = consortium.expect("valid consortium");
        let results = consortium.run().await;

        assert_eq!(results.len(), n);

        let aggregate_key = results[0].pubkey_package.verifying_key().serialize();

        for result in &results[1..] {
            assert_eq!(
                result.pubkey_package.verifying_key().serialize(),
                aggregate_key,
                "DKG did not converge for n={n}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_signing_with_dkg_key() {
    let consortium = Consortium::new(5).await.expect("consortium failed");
    let min_signers = consortium.sessions[0].1.min_signers as usize;
    let results = consortium.run().await;
    let group_key = results[0].pubkey_package.verifying_key();
    let msg = b"release the funds";

    let signers: Vec<&DkgResult> = results.iter().take(min_signers).collect();
    let sig = sign(&signers, msg).expect("signing failed");

    assert!(group_key.verify(msg, &sig).is_ok());
    assert!(group_key.verify(b"refund", &sig).is_err());

    let signers: Vec<&DkgResult> = results.iter().take(min_signers - 1).collect();
    if let Ok(sig) = sign(&signers, msg) {
        assert!(group_key.verify(msg, &sig).is_err());
    }
}

#[tokio::test]
async fn test_invalid_participant_lists_rejected() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let federation_id = dummy_federation_id();

    for n in [1, 2] {
        let participants = create_frost_participant(n);
        let result =
            FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db)
                .await;
        assert!(result.is_err(), "n={n} must be rejected");
    }

    // duplicate participant
    let mut participants = create_frost_participant(3);
    participants.push(participants[0].clone());
    let result =
        FrostDkgSessionRecord::new(participants[0].clone(), participants, federation_id, &db).await;
    assert!(result.is_err(), "duplicates must be rejected");

    // local participant is not in the list
    let participants = create_frost_participant(3);
    let outsider = create_frost_participant(1).remove(0);
    let result = FrostDkgSessionRecord::new(outsider, participants, federation_id, &db).await;
    assert!(result.is_err(), "outsider must be rejected");
}

#[tokio::test]
async fn test_session_id_ignores_participant_order() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let participants = create_frost_participant(4);
    let mut reversed = participants.clone();
    reversed.reverse();

    let a = FrostDkgSessionRecord::new(
        participants[0].clone(),
        participants.clone(),
        dummy_federation_id(),
        &db,
    )
    .await
    .unwrap();

    let db2 = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let b = FrostDkgSessionRecord::new(
        participants[0].clone(),
        reversed,
        dummy_federation_id(),
        &db2,
    )
    .await
    .unwrap();

    assert_eq!(a.session_id, b.session_id);
}

#[tokio::test]
async fn test_threshold_values() {
    // (participants, expected min signers)
    for (n, expected) in [(3, 3), (4, 3), (5, 4), (7, 5), (10, 7)] {
        let consortium = Consortium::new(n).await.unwrap();
        assert_eq!(consortium.sessions[0].1.min_signers, expected, "n={n}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_run_after_finish_returns_same_key() {
    let consortium = Consortium::new(3).await.unwrap();
    let (db, record) = consortium.sessions[0].clone();
    let session_id = consortium.session_id;
    let results = consortium.run().await;

    let transport = FileTransport::new(&session_id).await.unwrap();
    let again = record.run(&db, transport).await.expect("second run failed");

    assert_eq!(
        again.pubkey_package.verifying_key().serialize(),
        results[0].pubkey_package.verifying_key().serialize()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_over_iroh() {
    for n in [3, 4] {
        let consortium = Consortium::new(n).await.expect("consortium failed");
        let min_signers = consortium.sessions[0].1.min_signers as usize;
        let results = consortium.run_iroh().await;

        let first = results[0].pubkey_package.verifying_key().serialize();
        for result in &results {
            assert_eq!(result.pubkey_package.verifying_key().serialize(), first);
        }

        let signers: Vec<&DkgResult> = results.iter().take(min_signers).collect();
        let sig = sign(&signers, b"msg").expect("signing failed");
        assert!(
            results[0]
                .pubkey_package
                .verifying_key()
                .verify(b"msg", &sig)
                .is_ok()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dkg_runner_steps_over_iroh() {
    let consortium = Consortium::new(4).await.expect("consortium failed");
    let net = consortium.iroh_net().await;
    let n = consortium.participants.len();
    let min_signers = consortium.sessions[0].1.min_signers;
    let session_id = consortium.session_id;

    let mut handles = Vec::new();
    for (i, me) in consortium.participants.iter().cloned().enumerate() {
        let participants = consortium.participants.clone();
        let transport = net.transport(i, session_id);

        handles.push(spawn("iroh_dkg_transport", async move {
            let runner = DkgRunner::new(transport);

            let round1 = runner
                .run_round1(&session_id, &me, &participants, min_signers)
                .await
                .expect("round1 failed");
            // a package from every other participant, not from self runner
            assert_eq!(round1.round1_packages.len(), n - 1);
            assert!(!round1.round1_packages.contains_key(&me.identifier));

            let round2 = runner
                .run_round2(
                    &session_id,
                    &participants,
                    &me,
                    round1.round1_secret_package,
                    &round1.round1_packages,
                )
                .await
                .expect("round2 failed");
            assert_eq!(round2.round2_received.len(), n - 1);
            assert!(!round2.round2_received.contains_key(&me.identifier));

            runner
                .finalize(
                    &round1.round1_packages,
                    &round2.round2_secret_package,
                    &round2.round2_received,
                )
                .expect("finalize failed")
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.expect("task panicked"));
    }

    let group_key = results[0].pubkey_package.verifying_key();
    for r in &results {
        assert_eq!(
            r.pubkey_package.verifying_key().serialize(),
            group_key.serialize()
        );
    }

    let signers: Vec<&DkgResult> = results.iter().take(min_signers as usize).collect();
    let sig = sign(&signers, b"msg").expect("signing failed");
    assert!(group_key.verify(b"msg", &sig).is_ok());
}

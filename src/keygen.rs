use crate::config::ServerConfig;
use crate::peer::Peer;
use futures::future::try_join_all;
use hbbft::crypto::{PublicKey, PublicKeySet, SecretKey, SecretKeyShare};
use hbbft::sync_key_gen::{Ack, Part, PartOutcome, SyncKeyGen};
use hbbft::util::max_faulty;
use rand::Rng;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::iter::once;
use tbs::PublicKeyShare;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn generate_keys<R: Rng>(
    cfg: &ServerConfig,
    rng: &mut R,
    mut peers: HashMap<u16, TcpStream>,
) -> (
    Vec<(u16, TcpStream, PublicKey)>,
    PublicKeySet,
    SecretKey,
    SecretKeyShare,
    Vec<tbs::PublicKeyShare>,
    tbs::SecretKeyShare,
) {
    info!("Beginning distributed key generation");
    let hbbft_sec_key: SecretKey = rng.gen();
    let hbbft_pub_key = hbbft_sec_key.public_key();

    // Exchange pub keys
    for (_, peer_socket) in peers.iter_mut() {
        peer_socket
            .write_all(&hbbft_pub_key.to_bytes())
            .await
            .expect("Failed to send hbbft pub key to peer");
    }

    let mut peers = try_join_all(peers.into_iter().map(|(id, peer_socket)| {
        (async move |id: u16,
                     mut peer_socket: TcpStream|
                    -> Result<(u16, TcpStream, PublicKey), std::io::Error> {
            let mut key_buffer = [0u8; 48];
            peer_socket.read_exact(&mut key_buffer).await?;
            let hbbft_pub_key = PublicKey::from_bytes(key_buffer).unwrap();
            Ok((id, peer_socket, hbbft_pub_key))
        })(id, peer_socket)
    }))
    .await
    .expect("Error collecting peer pub keys");

    let pub_keys = once((cfg.identity, hbbft_pub_key.clone()))
        .chain(peers.iter().map(|(id, _, key)| (*id, key.clone())))
        .collect::<BTreeMap<_, _>>();

    // Generate proposal
    let thresh = max_faulty(cfg.federation_size as usize);
    debug!("Max faulty nodes: {}", thresh);
    let (mut kg, proposal) = SyncKeyGen::new(
        cfg.identity,
        hbbft_sec_key.clone(),
        pub_keys.clone(),
        thresh,
        rng,
    )
    .expect("Failed to instantiate keygen algorithm");

    let ack = kg
        .handle_part(&cfg.identity, proposal.clone().unwrap(), rng)
        .expect("Failed to accept own proposal");
    let ack = match ack {
        PartOutcome::Valid(Some(ack)) => ack,
        _ => {
            panic!()
        }
    };
    kg.handle_ack(&cfg.identity, ack.clone())
        .expect("Failed to handle own ack");

    // Distribute proposal
    let proposal_bin = bincode::serialize(proposal.as_ref().expect("No proposal was generated"))
        .expect("Can't encode proposal");
    let proposal_len = proposal_bin.len();
    for (peer, peer_socket, _) in peers.iter_mut() {
        peer_socket
            .write_u64(proposal_len as u64)
            .await
            .expect("Failed to send proposal len");
        peer_socket
            .write_all(&proposal_bin)
            .await
            .expect("Failed to send proposal");
        debug!("Sent proposal to node {}", peer);
    }

    // Receive and ack proposals
    let mut acks = vec![ack];
    for (peer, peer_socket, _) in peers.iter_mut() {
        let len = peer_socket
            .read_u64()
            .await
            .expect("Failed to read proposal len");

        let mut proposal_bin = vec![0; len as usize];
        peer_socket
            .read_exact(&mut proposal_bin)
            .await
            .expect("Failed to read proposal");
        let proposal: Part =
            bincode::deserialize(&proposal_bin).expect("Could not decode proposal");

        debug!("Received proposal from {}", peer);
        let ack = match kg
            .handle_part(peer, proposal, rng)
            .expect("Could not process proposal")
        {
            PartOutcome::Valid(Some(ack)) => ack,
            PartOutcome::Valid(None) => panic!("No ACK produced"),
            PartOutcome::Invalid(e) => {
                panic!("Invalid proposal: {:?}", e)
            }
        };

        acks.push(ack);
    }

    let mut ack_sent = 0;
    let mut ack_received = 0;
    // sending all acks to all peers
    for (peer, peer_socket, _) in peers.iter_mut() {
        debug!("Sending acks to {}", peer);
        for ack in acks.iter() {
            let ack_bin = bincode::serialize(ack).expect("Could not serialize ACK");
            let ack_len = ack_bin.len();
            peer_socket
                .write_u64(ack_len as u64)
                .await
                .expect("Failed to send ack len");
            peer_socket
                .write_all(&ack_bin)
                .await
                .expect("Failed to send ack");
            ack_sent += 1;
        }
    }

    for (peer, peer_socket, _) in peers.iter_mut() {
        for _ in 0..cfg.federation_size {
            let len = peer_socket
                .read_u64()
                .await
                .expect("Failed to read ack len");

            let mut ack_bin = vec![0; len as usize];
            peer_socket
                .read_exact(&mut ack_bin)
                .await
                .expect("Failed to read ack");
            let ack: Ack = bincode::deserialize(&ack_bin).expect("Could not decode proposal");

            kg.handle_ack(peer, ack).expect("Could not process ACK");
            ack_received += 1;
        }
        debug!("Received all ACKs from {}", peer);
    }

    assert_eq!(ack_sent, ack_received);
    assert!(kg.is_ready());
    let (pub_key_set, secret_key_share) = kg.generate().expect("Could not generate keys");

    info!("Finished generating keys");

    let (sk, pks) = fake_tbs_keygen(cfg.identity);
    (
        peers,
        pub_key_set,
        hbbft_sec_key,
        secret_key_share.unwrap(),
        pks,
        sk,
    )
}

// FIXME: implement dist key gen for TBS scheme or make dist keygen optional through config
fn fake_tbs_keygen(id: u16) -> (tbs::SecretKeyShare, Vec<tbs::PublicKeyShare>) {
    let sec_hex = [
        "2000000000000000459a4897f4d630953495e7a78b1eb2e0e71b0f8731133eff14cc1c3590b6c370",
        "2000000000000000457d7986563f38a89ebf3b8005c09254ba84cc5d4b148e563bf6e1ca259c8d08",
        "20000000000000004660aa75b7a73fbb07468e588205311c92c52b3e6ded17e1a99d448a0e294514",
        "20000000000000004743db64181047ce70cce030ff4acfe369068b1e8fc6a16b1845a749f7b5fc1f",
        "200000000000000048260c5479784ee1d95233097c906dab4147eafeb09f2bf686ec0909e042b42b",
    ];

    let sks = sec_hex
        .iter()
        .map(|&sk| {
            let bytes = hex::decode(sk).unwrap();
            bincode::deserialize(&bytes).unwrap()
        })
        .collect::<Vec<tbs::SecretKeyShare>>();
    let pks = sks
        .iter()
        .map(tbs::SecretKeyShare::to_pub_key_share)
        .collect::<Vec<_>>();

    (sks[id as usize], pks)
}

pub fn fake_pub_keys() -> Vec<tbs::PublicKeyShare> {
    fake_tbs_keygen(0).1
}

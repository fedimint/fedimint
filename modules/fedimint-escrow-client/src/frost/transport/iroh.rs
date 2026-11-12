use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::runtime::{sleep, spawn};
use fedimint_core::time::now;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::dkg::round1::Package as Round1Package;
use frost_secp256k1_tr::keys::dkg::round2::Package as Round2Package;
use futures::lock::Mutex;
use iroh::discovery::static_provider::StaticProvider;
use iroh::{Endpoint, NodeAddr, NodeId, SecretKey};

use crate::frost::session::SessionId;
use crate::frost::transport::{DkgTransport, SigningTransport, TransportError};

const ROUND1_TAG: u8 = 1;
const ROUND2_TAG: u8 = 2;
const SIGNING_TAG: u8 = 3;
const CONFIRM_TAG: u8 = 4;
const REQUEST_TAG: u8 = 5;

pub const DKG_ALPN: &[u8] = b"fedimint_escrow_iroh_dkg_consortium";
const MAX_MESSAGE_BYTES: usize = 128 * 1024;
const MAX_QUEUED_SIGNING_FRAMES: usize = 1024;
const PULL_INTERVAL: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Default)]
struct Inbox {
    round1: BTreeMap<Identifier, Vec<u8>>,
    round2: BTreeMap<Identifier, Vec<u8>>,
    confirmations: BTreeMap<Identifier, [u8; 32]>,
    signing: std::collections::VecDeque<(Identifier, Vec<u8>)>,
}

// what peer sent to other one who missed it
#[derive(Default)]
struct Outgoing {
    round1: Option<Vec<u8>>,
    round2: BTreeMap<Identifier, Vec<u8>>,
    confirmation: Option<Vec<u8>>,
}

impl Outgoing {
    fn get(&self, tag: u8, peer: &Identifier) -> Vec<u8> {
        match tag {
            ROUND1_TAG => self.round1.clone(),
            ROUND2_TAG => self.round2.get(peer).cloned(),
            CONFIRM_TAG => self.confirmation.clone(),
            _ => None,
        }
        .unwrap_or_default()
    }
}

impl Inbox {
    fn has(&self, tag: u8, id: &Identifier) -> bool {
        match tag {
            ROUND1_TAG => self.round1.contains_key(id),
            ROUND2_TAG => self.round2.contains_key(id),
            CONFIRM_TAG => self.confirmations.contains_key(id),
            _ => false,
        }
    }
}

fn store(inbox: &mut Inbox, sender: Identifier, tag: u8, payload: &[u8]) -> anyhow::Result<()> {
    match tag {
        ROUND1_TAG => {
            inbox.round1.insert(sender, payload.to_vec());
        }
        ROUND2_TAG => {
            inbox.round2.insert(sender, payload.to_vec());
        }
        SIGNING_TAG => {
            if inbox.signing.len() >= MAX_QUEUED_SIGNING_FRAMES {
                inbox.signing.pop_front();
            }
            inbox.signing.push_back((sender, payload.to_vec()));
        }
        CONFIRM_TAG => {
            let digest: [u8; 32] = payload
                .try_into()
                .map_err(|_| anyhow::anyhow!("a key confirmation is 32 bytes"))?;
            inbox.confirmations.insert(sender, digest);
        }
        _ => anyhow::bail!("unknown round tag"),
    }
    Ok(())
}

pub struct IrohDkgTransport {
    endpoint: Endpoint,
    session_id: SessionId,
    peers: BTreeMap<Identifier, NodeAddr>,
    inbox: Arc<Mutex<Inbox>>,
    outgoing: Arc<std::sync::Mutex<Outgoing>>,
    accept_task: fedimint_core::runtime::JoinHandle<()>,
}

impl IrohDkgTransport {
    pub async fn new(
        session_id: SessionId,
        secret: SecretKey,
        peers: BTreeMap<Identifier, NodeAddr>,
    ) -> Result<Self, TransportError> {
        let static_provider = StaticProvider::new();
        for addr in peers.values() {
            static_provider.add_node_info(addr.clone());
        }
        let endpoint = Endpoint::builder()
            .secret_key(secret)
            .alpns(vec![DKG_ALPN.to_vec()])
            .discovery(Box::new(static_provider))
            .bind()
            .await?;
        Ok(Self::from_endpoint(endpoint, session_id, peers))
    }

    pub fn from_endpoint(
        endpoint: Endpoint,
        session_id: SessionId,
        peers: BTreeMap<Identifier, NodeAddr>,
    ) -> Self {
        let inbox = Arc::new(Mutex::new(Inbox::default()));
        let outgoing = Arc::new(std::sync::Mutex::new(Outgoing::default()));
        let receiver_mapping: BTreeMap<NodeId, Identifier> =
            peers.iter().map(|(id, addr)| (addr.node_id, *id)).collect();

        let accept_endpoint = endpoint.clone();
        let accept_inbox = inbox.clone();
        let accept_outgoing = outgoing.clone();
        let accept_task = spawn("iroh-dkg-accept", async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let inbox = accept_inbox.clone();
                let outgoing = accept_outgoing.clone();
                let receiver_mapping = receiver_mapping.clone();
                spawn("iroh-dkg-handle-incoming", async move {
                    if let Err(e) =
                        handle_incoming(incoming, inbox, outgoing, receiver_mapping, session_id)
                            .await
                    {
                        tracing::warn!("iroh dkg transport: {e}");
                    }
                });
            }
        });

        Self {
            endpoint,
            session_id,
            peers,
            inbox,
            outgoing,
            accept_task,
        }
    }
    async fn send_tagged(
        &self,
        session_id: &SessionId,
        receiver: Identifier,
        tag: u8,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        self.validate_session(session_id)?;

        let receiver_addr = self
            .peers
            .get(&receiver)
            .ok_or(TransportError::InvalidReceiver)?;

        let conn = self
            .endpoint
            .connect(receiver_addr.clone(), DKG_ALPN)
            .await?;

        let (mut send, _recv) = conn.open_bi().await.map_err(TransportError::backend)?;

        send.write_all(&[tag])
            .await
            .map_err(TransportError::backend)?;
        send.write_all(&session_id.0)
            .await
            .map_err(TransportError::backend)?;
        send.write_all(payload)
            .await
            .map_err(TransportError::backend)?;
        send.finish().map_err(TransportError::backend)?;
        let _ = send.stopped().await;

        Ok(())
    }

    async fn push(
        &self,
        session_id: &SessionId,
        receiver: Identifier,
        tag: u8,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        match fedimint_core::runtime::timeout(
            IO_TIMEOUT,
            self.send_tagged(session_id, receiver, tag, payload),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(
                e @ (TransportError::InvalidReceiver | TransportError::SessionMismatch { .. }),
            )) => Err(e),
            Ok(Err(e)) => {
                tracing::debug!("push to {receiver:?} failed, they will pull it: {e}");
                Ok(())
            }
            Err(_) => {
                tracing::debug!("push to {receiver:?} timed out, they will pull it");
                Ok(())
            }
        }
    }

    // request a peer for its message of `tag`
    async fn get_tag_message(&self, peer: Identifier, tag: u8) -> Result<(), TransportError> {
        let addr = self
            .peers
            .get(&peer)
            .ok_or(TransportError::InvalidReceiver)?;
        let conn = self.endpoint.connect(addr.clone(), DKG_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(TransportError::backend)?;

        send.write_all(&[REQUEST_TAG])
            .await
            .map_err(TransportError::backend)?;
        send.write_all(&self.session_id.0)
            .await
            .map_err(TransportError::backend)?;
        send.write_all(&[tag])
            .await
            .map_err(TransportError::backend)?;
        send.finish().map_err(TransportError::backend)?;

        let bytes = recv
            .read_to_end(MAX_MESSAGE_BYTES)
            .await
            .map_err(TransportError::backend)?;
        conn.close(0u32.into(), b"fetched");

        if bytes.len() <= 33 {
            return Ok(()); // the peer has nothing for us yet
        }
        if bytes[0] != tag || bytes[1..33] != self.session_id.0[..] {
            return Err(TransportError::Serialization("unexpected reply".into()));
        }
        store(&mut *self.inbox.lock().await, peer, tag, &bytes[33..])
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    // waits until everyone in `expected` delivered `tag`, asking the missing ones
    // every few seconds
    async fn wait_for(
        &self,
        tag: u8,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<(), TransportError> {
        let deadline = now()
            .checked_add(timeout)
            .ok_or(TransportError::TimeoutError)?;
        let mut last_pull: Option<std::time::SystemTime> = None;

        loop {
            let missing: Vec<Identifier> = {
                let inbox = self.inbox.lock().await;
                expected
                    .iter()
                    .filter(|id| *id != self_id && !inbox.has(tag, id))
                    .copied()
                    .collect()
            };
            if missing.is_empty() {
                return Ok(());
            }
            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }

            let due = last_pull
                .is_none_or(|t| now().duration_since(t).unwrap_or_default() >= PULL_INTERVAL);
            if due {
                last_pull = Some(now());
                futures::future::join_all(missing.into_iter().map(|id| async move {
                    match fedimint_core::runtime::timeout(IO_TIMEOUT, self.get_tag_message(id, tag))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::debug!("pull from {id:?} failed: {e}"),
                        Err(_) => tracing::debug!("pull from {id:?} timed out"),
                    }
                }))
                .await;
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    fn validate_session(&self, session_id: &SessionId) -> Result<(), TransportError> {
        if *session_id != self.session_id {
            return Err(TransportError::SessionMismatch {
                expected: self.session_id,
                actual: *session_id,
            });
        }

        Ok(())
    }
}

impl Drop for IrohDkgTransport {
    fn drop(&mut self) {
        self.accept_task.abort();
        let endpoint = self.endpoint.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                endpoint.close().await;
            });
        }
    }
}

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    inbox: Arc<Mutex<Inbox>>,
    outgoing: Arc<std::sync::Mutex<Outgoing>>,
    receiver_mapping: BTreeMap<NodeId, Identifier>,
    expected_session_id: SessionId,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_node_id()?;

    let Some(&sender) = receiver_mapping.get(&remote) else {
        anyhow::bail!("connection from unrecognized peer {remote}");
    };

    let (mut send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(MAX_MESSAGE_BYTES).await?;

    if bytes.len() < 33 {
        anyhow::bail!("message too short to contain tag & session_id");
    }
    let tag = bytes[0];
    let msg_session_id = SessionId(bytes[1..33].try_into().expect("message too short"));
    let payload = &bytes[33..];

    if msg_session_id != expected_session_id {
        anyhow::bail!(
            "message dropped from {sender:?} carries session {msg_session_id:?}, expected {expected_session_id:?}"
        );
    }

    if tag == REQUEST_TAG {
        let wanted_tag = *payload
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty request"))?;

        let reply = outgoing.lock().unwrap().get(wanted_tag, &sender);
        send.write_all(&[wanted_tag]).await?;
        send.write_all(&expected_session_id.0).await?;
        send.write_all(&reply).await?;
        send.finish()?;
        let _ = send.stopped().await;
        return Ok(());
    }

    store(&mut *inbox.lock().await, sender, tag, payload)
}

#[async_trait]
impl DkgTransport for IrohDkgTransport {
    async fn broadcast_round1(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        package: Round1Package,
    ) -> Result<(), TransportError> {
        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        self.outgoing.lock().unwrap().round1 = Some(bytes.clone());

        let ids: Vec<Identifier> = self
            .peers
            .keys()
            .filter(|id| *id != sender)
            .copied()
            .collect();
        let results = futures::future::join_all(
            ids.iter()
                .map(|id| self.push(session_id, *id, ROUND1_TAG, &bytes)),
        )
        .await;
        results.into_iter().collect()
    }

    async fn recv_round1_all(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, Round1Package>, TransportError> {
        self.validate_session(session_id)?;
        self.wait_for(ROUND1_TAG, self_id, expected, timeout)
            .await?;

        let inbox = self.inbox.lock().await;
        inbox
            .round1
            .iter()
            .filter(|(id, _)| expected.contains(id))
            .map(|(id, bytes)| {
                Round1Package::deserialize(bytes)
                    .map(|pkg| (*id, pkg))
                    .map_err(|e| TransportError::Serialization(e.to_string()))
            })
            .collect()
    }

    async fn send_round2(
        &self,
        session_id: &SessionId,
        _sender: &Identifier,
        receiver: &Identifier,
        package: Round2Package,
    ) -> Result<(), TransportError> {
        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        self.outgoing
            .lock()
            .unwrap()
            .round2
            .insert(*receiver, bytes.clone());
        self.push(session_id, *receiver, ROUND2_TAG, &bytes).await
    }

    async fn recv_round2(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, Round2Package>, TransportError> {
        self.validate_session(session_id)?;
        self.wait_for(ROUND2_TAG, self_id, expected, timeout)
            .await?;

        let inbox = self.inbox.lock().await;
        inbox
            .round2
            .iter()
            .filter(|(id, _)| expected.contains(id))
            .map(|(id, bytes)| {
                Round2Package::deserialize(bytes)
                    .map(|pkg| (*id, pkg))
                    .map_err(|e| TransportError::Serialization(e.to_string()))
            })
            .collect()
    }

    async fn broadcast_confirmation(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        digest: [u8; 32],
    ) -> Result<(), TransportError> {
        self.outgoing.lock().unwrap().confirmation = Some(digest.to_vec());

        let ids: Vec<Identifier> = self
            .peers
            .keys()
            .filter(|id| *id != sender)
            .copied()
            .collect();
        let results = futures::future::join_all(
            ids.iter()
                .map(|id| self.push(session_id, *id, CONFIRM_TAG, &digest)),
        )
        .await;
        results.into_iter().collect()
    }

    async fn recv_confirmations(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, [u8; 32]>, TransportError> {
        self.validate_session(session_id)?;
        self.wait_for(CONFIRM_TAG, self_id, expected, timeout)
            .await?;

        let inbox = self.inbox.lock().await;
        Ok(inbox
            .confirmations
            .iter()
            .filter(|(id, _)| expected.contains(id))
            .map(|(id, digest)| (*id, *digest))
            .collect())
    }
}

#[async_trait]
impl SigningTransport for IrohDkgTransport {
    async fn send(
        &self,
        _sender: &Identifier,
        receiver: &Identifier,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        // the frame carries the consortium session id, signing.rs puts the escrow id
        // inside
        self.send_tagged(&self.session_id, *receiver, SIGNING_TAG, &payload)
            .await
    }

    async fn recv(
        &self,
        _self_id: &Identifier,
        timeout: Duration,
    ) -> Result<(Identifier, Vec<u8>), TransportError> {
        let deadline = now()
            .checked_add(timeout)
            .ok_or(TransportError::TimeoutError)?;

        loop {
            if let Some(message) = self.inbox.lock().await.signing.pop_front() {
                return Ok(message);
            }
            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

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
use crate::frost::transport::{DkgTransport, TransportError};

const ROUND1_TAG: u8 = 1;
const ROUND2_TAG: u8 = 2;
pub const DKG_ALPN: &[u8] = b"fedimint_escrow_iroh_dkg_consortium";

#[derive(Default)]
struct Inbox {
    round1: BTreeMap<Identifier, Vec<u8>>,
    round2: BTreeMap<Identifier, Vec<u8>>,
}

pub struct IrohDkgTransport {
    endpoint: Endpoint,
    session_id: SessionId,
    peers: BTreeMap<Identifier, NodeAddr>,
    inbox: Arc<Mutex<Inbox>>,
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
        let receiver_mapping: BTreeMap<NodeId, Identifier> =
            peers.iter().map(|(id, addr)| (addr.node_id, *id)).collect();

        let accept_endpoint = endpoint.clone();
        let accept_inbox = inbox.clone();
        spawn("iroh-dkg-accept", async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let inbox = accept_inbox.clone();
                let receiver_mapping = receiver_mapping.clone();
                spawn("iroh-dkg-handle-incoming", async move {
                    if let Err(e) =
                        handle_incoming(incoming, inbox, receiver_mapping, session_id).await
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
        }
    }
    async fn send_tagged(
        &self,
        session_id: &SessionId,
        receiver: Identifier,
        tag: u8,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        if *session_id != self.session_id {
            return Err(TransportError::SessionMismatch {
                expected: self.session_id,
                actual: *session_id,
            });
        }
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
}

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    inbox: Arc<Mutex<Inbox>>,
    receiver_mapping: BTreeMap<NodeId, Identifier>,
    expected_session_id: SessionId,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let remote = conn.remote_node_id()?;

    let Some(&sender) = receiver_mapping.get(&remote) else {
        anyhow::bail!("connection from unrecognized peer {remote}");
    };

    let (_send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(10 * 1024 * 1024).await?;

    if bytes.len() < 33 {
        anyhow::bail!("message too short to contain tag + session_id");
    }
    let tag = bytes[0];
    let msg_session_id = SessionId(bytes[1..33].try_into().expect("message too short"));
    let payload = &bytes[33..];

    if msg_session_id != expected_session_id {
        anyhow::bail!(
            "message dropped from {sender:?} carries session {msg_session_id:?}, expected {expected_session_id:?}"
        );
    }

    let mut inbox = inbox.lock().await;
    match tag {
        ROUND1_TAG => {
            inbox.round1.insert(sender, payload.to_vec());
        }
        ROUND2_TAG => {
            inbox.round2.insert(sender, payload.to_vec());
        }
        _ => anyhow::bail!("unknown round tag"),
    }
    Ok(())
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
        for id in self.peers.keys() {
            if id == sender {
                continue;
            }
            self.send_tagged(session_id, *id, ROUND1_TAG, &bytes)
                .await?;
        }
        Ok(())
    }

    async fn recv_round1_all(
        &self,
        _session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, Round1Package>, TransportError> {
        let deadline = now()
            .checked_add(timeout)
            .ok_or(TransportError::TimeoutError)?;

        loop {
            {
                let inbox = self.inbox.lock().await;
                let ready = expected
                    .iter()
                    .filter(|id| **id != *self_id)
                    .all(|id| inbox.round1.contains_key(id));
                if ready {
                    return inbox
                        .round1
                        .iter()
                        .filter(|(id, _)| expected.contains(id))
                        .map(|(id, bytes)| {
                            Round1Package::deserialize(bytes)
                                .map(|pkg| (*id, pkg))
                                .map_err(|e| TransportError::Serialization(e.to_string()))
                        })
                        .collect();
                }
            }
            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }
            sleep(Duration::from_millis(200)).await;
        }
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
        self.send_tagged(session_id, *receiver, ROUND2_TAG, &bytes)
            .await
    }

    async fn recv_round2(
        &self,
        _session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, Round2Package>, TransportError> {
        let deadline = now()
            .checked_add(timeout)
            .ok_or(TransportError::TimeoutError)?;

        loop {
            {
                let inbox = self.inbox.lock().await;
                let ready = expected
                    .iter()
                    .filter(|id| **id != *self_id)
                    .all(|id| inbox.round2.contains_key(id));
                if ready {
                    return inbox
                        .round2
                        .iter()
                        .filter(|(id, _)| expected.contains(id))
                        .map(|(id, bytes)| {
                            Round2Package::deserialize(bytes)
                                .map(|pkg| (*id, pkg))
                                .map_err(|e| TransportError::Serialization(e.to_string()))
                        })
                        .collect();
                }
            }
            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }
            sleep(Duration::from_millis(200)).await;
        }
    }
}

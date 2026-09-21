use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::runtime::sleep;
use fedimint_core::time::now;
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{round1, round2};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::frost::session::SessionId;
use crate::frost::transport::{DkgTransport, TransportError};

pub struct FileTransport {
    root: PathBuf,
    session_id: SessionId,
    poll_interval: Duration,
}

#[async_trait]
impl DkgTransport for FileTransport {
    async fn broadcast_round1(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        package: round1::Package,
    ) -> Result<(), TransportError> {
        self.check_session(session_id)?;

        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        self.write_atomic(&self.round1_path(*sender), &bytes).await
    }

    async fn recv_round1_all(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, round1::Package>, TransportError> {
        self.check_session(session_id)?;

        let paths: BTreeMap<_, _> = expected
            .iter()
            .filter(|id| **id != *self_id)
            .map(|id| (*id, self.round1_path(*id)))
            .collect();

        self.poll_until_all(paths, timeout, |bytes| {
            round1::Package::deserialize(bytes)
                .map_err(|e| TransportError::Serialization(e.to_string()))
        })
        .await
    }

    async fn send_round2(
        &self,
        session_id: &SessionId,
        sender: &Identifier,
        receiver: &Identifier,
        package: round2::Package,
    ) -> Result<(), TransportError> {
        self.check_session(session_id)?;

        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        self.write_atomic(&self.round2_path(*sender, *receiver), &bytes)
            .await
    }

    async fn recv_round2(
        &self,
        session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, round2::Package>, TransportError> {
        self.check_session(session_id)?;

        let paths: BTreeMap<_, _> = expected
            .iter()
            .filter(|id| **id != *self_id)
            .map(|id| (*id, self.round2_path(*id, *self_id)))
            .collect();

        self.poll_until_all(paths, timeout, |bytes| {
            round2::Package::deserialize(bytes)
                .map_err(|e| TransportError::Serialization(e.to_string()))
        })
        .await
    }
}

impl FileTransport {
    pub async fn new(session_id: &SessionId) -> Result<Self, TransportError> {
        let root = std::env::temp_dir()
            .join("fedimint-escrow-dkg")
            .join(hex::encode(session_id.0));

        fs::create_dir_all(&root).await?;

        Ok(Self {
            root,
            session_id: *session_id,
            poll_interval: Duration::from_millis(200),
        })
    }

    fn round1_path(&self, id: Identifier) -> PathBuf {
        self.root
            .join("round1")
            .join(format!("{}.json", hex::encode(id.serialize())))
    }

    fn round2_path(&self, sender: Identifier, receiver: Identifier) -> PathBuf {
        self.root
            .join("round2")
            .join(hex::encode(receiver.serialize()))
            .join(format!("{}.json", hex::encode(sender.serialize())))
    }
    async fn write_atomic(&self, path: &PathBuf, bytes: &[u8]) -> Result<(), TransportError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let tmp = path.with_extension("tmp");

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .await?;

        file.write_all(bytes).await?;
        file.flush().await?;
        file.sync_all().await?;

        drop(file);

        fs::rename(&tmp, path).await?;

        Ok(())
    }

    async fn poll_until_all<Item, F>(
        &self,
        paths: BTreeMap<Identifier, PathBuf>,
        timeout: Duration,
        deserialize: F,
    ) -> Result<BTreeMap<Identifier, Item>, TransportError>
    where
        F: Fn(&[u8]) -> Result<Item, TransportError>,
    {
        let deadline = now()
            .checked_add(timeout)
            .ok_or(TransportError::TimeoutError)?;

        let mut collected = BTreeMap::new();

        loop {
            let mut still_missing = false;

            for (id, path) in &paths {
                if collected.contains_key(id) {
                    continue;
                }

                match fs::read(path).await {
                    Ok(bytes) => {
                        collected.insert(*id, deserialize(&bytes)?);
                    }
                    Err(_) => {
                        still_missing = true;
                    }
                }
            }

            if !still_missing {
                return Ok(collected);
            }

            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }

            sleep(self.poll_interval).await;
        }
    }

    fn check_session(&self, session_id: &SessionId) -> Result<(), TransportError> {
        if *session_id != self.session_id {
            return Err(TransportError::SessionMismatch {
                expected: self.session_id,
                actual: *session_id,
            });
        }
        Ok(())
    }

    /// Deletes this session's entire scratch directory. Only safe to call
    /// once every participant has independently reached a terminal state
    /// for this session.
    pub async fn remove_data(&self) -> Result<(), TransportError> {
        match fs::remove_dir_all(&self.root).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TransportError::IoError(e)),
        }
    }
}

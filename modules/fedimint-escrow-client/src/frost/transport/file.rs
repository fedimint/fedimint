use std::collections::BTreeMap;
use std::fs::{self, create_dir_all, remove_dir_all};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::time::now;
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{round1, round2};

use crate::frost::session::SessionId;
use crate::frost::transport::{DkgTransport, TransportError};

pub struct FileTransport {
    root: PathBuf,
    session_id: SessionId,
    max_signers: u16,
    poll_interval: Duration,
}

#[async_trait]
impl DkgTransport for FileTransport {
    async fn broadcast_round1(
        &self,
        _session_id: &SessionId,
        sender: &Identifier,
        package: round1::Package,
    ) -> Result<(), TransportError> {
        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        self.write_atomic(&self.round1_path(*sender), &bytes).await
    }

    async fn recv_round1_all(
        &self,
        _session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, round1::Package>, TransportError> {
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
        _session_id: &SessionId,
        sender: &Identifier,
        receiver: &Identifier,
        package: round2::Package,
    ) -> Result<(), TransportError> {
        let bytes = package
            .serialize()
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        self.write_atomic(&self.round2_path(*sender, *receiver), &bytes)
            .await
    }

    async fn recv_round2(
        &self,
        _session_id: &SessionId,
        self_id: &Identifier,
        expected: &[Identifier],
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, round2::Package>, TransportError> {
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
    pub fn new(path: &String, session_id: &SessionId, max_signers: u16) -> std::io::Result<Self> {
        let root = PathBuf::from(path);

        if !root.exists() {
            fs::create_dir(path)?;
        }

        let root_path = root.join(hex::encode(session_id.0));

        let transport = Self {
            root: root_path,
            session_id: *session_id,
            max_signers,
            poll_interval: Duration::from_millis(200),
        };

        transport.initialize()?;

        Ok(transport)
    }

    fn initialize(&self) -> std::io::Result<()> {
        let round1 = self.root.join("round1");
        let round2 = self.root.join("round2");

        create_dir_all(&round1)?;
        create_dir_all(&round2)?;

        // Round 1 files
        for participant in 1..=self.max_signers {
            let round1_participant_slot = round1.join(format!("participant_{}.json", participant));

            if !round1_participant_slot.exists() {
                fs::File::create(round1_participant_slot)?;
            }
        }

        // Round 2 directories/files
        for sender in 1..=self.max_signers {
            let sender_dir = round2.join(format!("participant_{}", sender));

            fs::create_dir_all(&sender_dir)?;

            for receiver in 1..=self.max_signers {
                if sender == receiver {
                    continue;
                }

                let slot = sender_dir.join(format!("participant_{}.json", receiver));

                if !slot.exists() {
                    fs::File::create(slot)?;
                }
            }
        }

        Ok(())
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

    /// Write-to-temp-then-rename so a concurrent reader never observes a
    /// partially written file.
    async fn write_atomic(&self, path: &PathBuf, bytes: &[u8]) -> Result<(), TransportError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("tmp");

        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, path)?;

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
            let mut still_missing = Vec::new();

            for (id, path) in &paths {
                if collected.contains_key(id) {
                    continue;
                }

                match fs::read(path) {
                    Ok(bytes) => {
                        collected.insert(*id, deserialize(&bytes)?);
                    }
                    Err(_) => {
                        still_missing.push(*id);
                    }
                }
            }

            if still_missing.is_empty() {
                return Ok(collected);
            }

            if now() >= deadline {
                return Err(TransportError::TimeoutError);
            }

            sleep(self.poll_interval);
        }
    }

    pub fn remove_data(&self) -> std::io::Result<()> {
        if self.root.exists() {
            remove_dir_all(&self.root)?;
        }

        Ok(())
    }
}

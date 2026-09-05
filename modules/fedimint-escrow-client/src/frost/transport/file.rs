use std::fs::{self, create_dir_all, remove_dir_all};
use std::path::PathBuf;

use fedimint_core::bitcoin::io;

use crate::frost::session::SessionId;
use crate::frost::transport::{self, DkgTransport};

pub struct FileTransport {
    root: PathBuf,
    session_id: SessionId,
    max_signers: u16,
}

impl DkgTransport for FileTransport {
    type Error = io::Error;

    fn broadcast_round1(
        &mut self,
        session_id: &SessionId,
        sender: frost_secp256k1::Identifier,
        package: frost_secp256k1::keys::dkg::round1::Package,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn recv_round1(
        &self,
        session_id: &SessionId,
        receiver: frost_secp256k1::Identifier,
    ) -> Result<
        std::collections::BTreeMap<
            frost_secp256k1::Identifier,
            frost_secp256k1::keys::dkg::round1::Package,
        >,
        Self::Error,
    > {
        todo!()
    }

    fn send_round2(
        &mut self,
        session_id: &SessionId,
        sender: frost_secp256k1::Identifier,
        receiver: frost_secp256k1::Identifier,
        package: frost_secp256k1::keys::dkg::round2::Package,
    ) -> Result<(), Self::Error> {
        todo!()
    }
    fn recv_round2(
        &self,
        session_id: &SessionId,
        receiver: frost_secp256k1::Identifier,
    ) -> Result<
        std::collections::BTreeMap<
            frost_secp256k1::Identifier,
            frost_secp256k1::keys::dkg::round2::Package,
        >,
        Self::Error,
    > {
        todo!()
    }
}

impl FileTransport {
    pub fn new(path: &String, session_id: &SessionId, max_signers: &u16) -> std::io::Result<Self> {
        let root = PathBuf::from(path);
        if !root.exists() {
            fs::create_dir(path);
        }
        let root_path = root.join(hex::encode(session_id.0));

        let transport = Self {
            root: root_path,
            session_id,
            max_signers,
        };
        transport.initialize()?;
        Ok(transport)
    }

    fn initialize(&self) -> std::io::Result<()> {
        let round1 = self.root.join("round1");
        let round2 = self.root.join("round2");
        create_dir_all(round1);
        create_dir_all(round2);

        // round1 directories
        for participant in ..=self.max_signers {
            let round1_participant_slot = round1.join(format!("participant_{}", participant + 1));
            if !round1_participant_slot.exists() {
                fs::File::create(format!("{}.json", round1_participant_slot));
            }
        }

        // round2 directories
        for sender in 1..=self.max_signers {
            let sender_dir = round2.join(format!("participant_", sender));

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

    pub fn remove_data(&self) -> std::io::Result<()> {
        if self.root.exists() {
            remove_dir_all(self.root);
        }
        Ok(())
    }
}

use std::collections::BTreeMap;

use frost_secp256k1::keys::dkg::round1::SecretPackage;
use frost_secp256k1::keys::dkg::round2::SecretPackage;
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use ring::rand::SystemRandom;

use crate::frost::session::FrostSessionArgs;
use crate::frost::transport::DkgTransport;

pub struct DkgRound1 {}

pub struct DkgRound2 {}

pub struct DkgResult {
    key_package: KeyPackage,
    pub_key_package: PublicKeyPackage,
}

pub struct DkgState {
    round1_secret: SecretPackage,
    round2_secret: Option<SecretPackage>,
}

pub struct DkgError {}

pub struct DkgRunner<T> {
    transport: T,
}

impl<T: DkgTransport> DkgRunner<DkgTransport> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn run_dkg(&mut self, args: &FrostSessionArgs) {
        let mut rng = SystemRandom::new();
        let min_participants = 3;
        let max_participants = 5;
        // To keep a record of every participants secret packages for further use, but
        // in reality no one will really keep any record or other participants
        // regarding this, just only there!
        let mut round1_secret_packages = BTreeMap::new();
        let mut received_round1_packages = BTreeMap::new();
        // for demonstration we are going with the loop, but particularly every
        // participants will run it in thier own envirnoment
        for participant_index in 1..=max_participants {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let (round1_secret_package, round1_package) = frost_secp256k1::keys::dkg::part1(
                participant_identifier,
                max_participants,
                max_participants,
                &mut rng,
            )?;
            round1_secret_packages.insert(participant_identifier, round1_secret_package);

            for reciever_participant_index in 1..max_participants {
                if reciever_participant_index == participant_index {
                    continue;
                }
                let reciever_participant_identifier = reciever_participant_index
                    .try_into()
                    .expect("should be nonzero");
                received_round1_packages
                    .entry(reciever_participant_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round1_package.clone());
            }
        }

        let mut round2_secret_packages = BTreeMap::new();
        let mut received_round2_packages = BTreeMap::new();

        for participant_index in 1..=max_participants {
            let participant_identifier = *participant_index.try_into().expect("should be nonzero");
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round1_secret_package = round1_secret_packages
                .remove(participant_identifier)
                .unwrap();
            let (round2_secret_package, round2_packages) =
                frost_secp256k1::keys::dkg::part2(round1_secret_package, round1_packages)?;

            round2_secret_packages.insert(participant_identifier, round2_secret_package);

            for (receiver_identifier, round2_package) in round2_packages {
                received_round2_packages
                    .entry(receiver_identifier)
                    .or_insert_with(BTreeMap::new)
                    .insert(participant_identifier, round2_package);
            }
        }

        let mut key_packages = BTreeMap::new();

        let mut pubkey_packages = BTreeMap::new();

        // For each participant, perform the third part of the DKG protocol.
        // In practice, each participant will perform this on their own environments.
        for participant_index in 1..=max_participants {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let round2_secret_package = &round2_secret_packages[&participant_identifier];
            let round1_packages = &received_round1_packages[&participant_identifier];
            let round2_packages = &received_round2_packages[&participant_identifier];
            let (key_package, pubkey_package) = frost_secp256k1::keys::dkg::part3(
                round2_secret_package,
                round1_packages,
                round2_packages,
            )?;
            key_packages.insert(participant_identifier, key_package);
            pubkey_packages.insert(participant_identifier, pubkey_package);
        }
        Ok(())
    }
}

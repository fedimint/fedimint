use std::collections::BTreeMap;

use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};

use crate::{MetaKey, MetaValue};

/// Submit a change of value for a given key. Guardians only.
pub const SUBMIT_ENDPOINT: &str = "submit";
/// Get consensus on the value of a given key
pub const GET_CONSENSUS_ENDPOINT: &str = "get_consensus";
/// Get revision of the consensus on the value of a given key
///
/// This is meant to avoid transmitting the whole value over
/// and over to clients that already have it, and are just checking
/// if it was updated.
pub const GET_CONSENSUS_REV_ENDPOINT: &str = "get_consensus_rev";
/// Get the list of pending submissions for a given key. Guardians only.
pub const GET_SUBMISSIONS_ENDPOINT: &str = "get_submission";

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitRequest {
    pub key: MetaKey,
    pub value: MetaValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetConsensusRequest(pub MetaKey);

#[derive(Debug, Serialize, Deserialize)]
pub struct GetSubmissionsRequest(pub MetaKey);

pub type GetSubmissionResponse = BTreeMap<PeerId, MetaValue>;

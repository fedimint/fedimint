use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

use fedimint_core::core::{ModuleInstanceId, OperationId};
use fedimint_core::db::WriteDatabaseTransaction;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::{apply, async_trait_maybe_send, maybe_add_send_sync};

use super::DynState;
use crate::{AddStateMachinesResult, DynGlobalClientContext};

pub type ContextGen =
    Arc<maybe_add_send_sync!(dyn Fn(ModuleInstanceId, OperationId) -> DynGlobalClientContext)>;

/// A state that is able to make progress eventually
#[derive(Debug)]
pub struct ActiveStateKey {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    // TODO: state being a key... seems ... risky?
    pub state: DynState,
}

impl ActiveStateKey {
    pub fn from_state(state: DynState) -> ActiveStateKey {
        ActiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl Encodable for ActiveStateKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.operation_id.consensus_encode(writer)?;
        self.state.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for ActiveStateKey {
    fn consensus_decode_partial<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode_partial(reader, modules)?;
        let state = DynState::consensus_decode_partial(reader, modules)?;

        Ok(ActiveStateKey {
            operation_id,
            state,
        })
    }
}

#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct ActiveStateMeta {
    pub created_at: SystemTime,
}

impl ActiveStateMeta {
    pub fn into_inactive(self) -> InactiveStateMeta {
        InactiveStateMeta {
            created_at: self.created_at,
            exited_at: fedimint_core::time::now(),
        }
    }
}

impl Default for ActiveStateMeta {
    fn default() -> Self {
        Self {
            created_at: fedimint_core::time::now(),
        }
    }
}

/// A past or final state of a state machine
#[derive(Debug, Clone)]
pub struct InactiveStateKey {
    // TODO: remove redundant operation id from state trait
    pub operation_id: OperationId,
    pub state: DynState,
}

impl InactiveStateKey {
    pub fn from_state(state: DynState) -> InactiveStateKey {
        InactiveStateKey {
            operation_id: state.operation_id(),
            state,
        }
    }
}

impl Encodable for InactiveStateKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.operation_id.consensus_encode(writer)?;
        self.state.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for InactiveStateKey {
    fn consensus_decode_partial<R: Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let operation_id = OperationId::consensus_decode_partial(reader, modules)?;
        let state = DynState::consensus_decode_partial(reader, modules)?;

        Ok(InactiveStateKey {
            operation_id,
            state,
        })
    }
}

#[derive(Debug, Copy, Clone, Decodable, Encodable)]
pub struct InactiveStateMeta {
    pub created_at: SystemTime,
    pub exited_at: SystemTime,
}

#[apply(async_trait_maybe_send!)]
pub trait IExecutor {
    async fn get_active_states(&self) -> Vec<(DynState, ActiveStateMeta)>;

    async fn add_state_machines_dbtx(
        &self,
        dbtx: &mut WriteDatabaseTransaction<'_>,
        states: Vec<DynState>,
    ) -> AddStateMachinesResult;
}

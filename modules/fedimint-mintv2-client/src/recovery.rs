use std::collections::BTreeMap;

use fedimint_client::module::init::recovery::{RecoveryFromHistory, RecoveryFromHistoryCommon};
use fedimint_client::module::init::ClientModuleRecoverArgs;
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::ClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{apply, async_trait_maybe_send, OutPoint};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::{MintInput, MintOutput};
use tracing::trace;

use crate::client_db::{RecoveryFinalizedKey, RecoveryStateKey};
use crate::issuance::NoteIssuanceRequest;
use crate::output::{MintOutputStateMachine, OutputSMCommon, OutputSMState};
use crate::{MintClientInit, MintClientModule, MintClientStateMachines};

#[derive(Clone, Debug)]
pub struct MintRecovery {
    state: MintRecoveryState,
    root_secret: DerivableSecret,
    client_ctx: ClientContext<MintClientModule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Decodable, Encodable)]
pub struct MintRecoveryState {
    requests: BTreeMap<PublicKey, NoteIssuanceRequest>,
}

#[apply(async_trait_maybe_send!)]
impl RecoveryFromHistory for MintRecovery {
    type Init = MintClientInit;

    async fn new(
        _init: &Self::Init,
        args: &ClientModuleRecoverArgs<Self::Init>,
        snapshot: Option<&NoModuleBackup>,
    ) -> anyhow::Result<(Self, u64)> {
        assert!(snapshot.is_none());

        let recovery = MintRecovery {
            state: MintRecoveryState {
                requests: BTreeMap::new(),
            },
            root_secret: args.module_root_secret().clone(),
            client_ctx: args.context(),
        };

        Ok((recovery, 0))
    }

    async fn load_dbtx(
        _init: &Self::Init,
        dbtx: &mut DatabaseTransaction<'_>,
        args: &ClientModuleRecoverArgs<Self::Init>,
    ) -> anyhow::Result<Option<(Self, RecoveryFromHistoryCommon)>> {
        dbtx.ensure_isolated()
            .expect("Must be in prefixed database");

        Ok(dbtx
            .get_value(&RecoveryStateKey)
            .await
            .map(|(state, common)| {
                (
                    MintRecovery {
                        state,
                        root_secret: args.module_root_secret().clone(),
                        client_ctx: args.context(),
                    },
                    common,
                )
            }))
    }

    async fn store_dbtx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        common: &RecoveryFromHistoryCommon,
    ) {
        dbtx.ensure_isolated()
            .expect("Must be in prefixed database");

        dbtx.insert_entry(&RecoveryStateKey, &(self.state.clone(), common.clone()))
            .await;
    }

    async fn delete_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) {
        dbtx.remove_entry(&RecoveryStateKey).await;
    }

    async fn load_finalized(dbtx: &mut DatabaseTransaction<'_>) -> Option<bool> {
        dbtx.get_value(&RecoveryFinalizedKey).await
    }

    async fn store_finalized(dbtx: &mut DatabaseTransaction<'_>, state: bool) {
        dbtx.insert_entry(&RecoveryFinalizedKey, &state).await;
    }

    async fn handle_input(
        &mut self,
        _client_ctx: &ClientContext<MintClientModule>,
        _idx: usize,
        input: &MintInput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        match input {
            MintInput::V0(input) => {
                self.state.requests.remove(&input.note.nonce);
            }
            MintInput::Default { variant, .. } => {
                trace!("Ignoring future mint input variant {variant}");
            }
        }

        Ok(())
    }

    async fn handle_output(
        &mut self,
        _client_ctx: &ClientContext<MintClientModule>,
        _out_point: OutPoint,
        output: &MintOutput,
        _session_idx: u64,
    ) -> anyhow::Result<()> {
        match output {
            MintOutput::V0(output) => {
                if let Some(request) =
                    NoteIssuanceRequest::recover(output.clone(), &self.root_secret)
                {
                    self.state
                        .requests
                        .insert(request.keypair(&self.root_secret).public_key(), request);
                }
            }
            MintOutput::Default { variant, .. } => {
                trace!("Ignoring future mint output variant {variant}");
            }
        };

        Ok(())
    }

    async fn finalize_dbtx(&self, dbtx: &mut DatabaseTransaction<'_>) -> anyhow::Result<()> {
        self.client_ctx
            .add_state_machines_dbtx(
                dbtx,
                self.client_ctx
                    .map_dyn(vec![MintClientStateMachines::Output(
                        MintOutputStateMachine {
                            common: OutputSMCommon {
                                operation_id: OperationId::new_random(),
                                range: None,
                                issuance_requests: self.state.requests.values().cloned().collect(),
                            },
                            state: OutputSMState::Pending,
                        },
                    )])
                    .collect(),
            )
            .await?;

        Ok(())
    }
}

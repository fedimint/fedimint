use std::cmp;
use std::time::{Duration, SystemTime};

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::task::sleep;
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_wallet_common::tweakable::Tweakable;
use fedimint_wallet_common::txoproof::PegInProof;
use fedimint_wallet_common::WalletInput;
use tracing::{debug, instrument, trace, warn};

use crate::api::WalletFederationApi;
use crate::pegin_monitor::filter_onchain_deposit_outputs;
use crate::WalletClientContext;

const TRANSACTION_STATUS_FETCH_INTERVAL: Duration = Duration::from_secs(1);

// FIXME: deal with RBF
// FIXME: deal with multiple deposits
#[cfg_attr(doc, aquamarine::aquamarine)]
/// The state machine driving forward a deposit (aka peg-in).
///
/// ```mermaid
/// graph LR
///     Created -- Transaction seen --> AwaitingConfirmations["Waiting for confirmations"]
///     AwaitingConfirmations -- Confirmations received --> Claiming
///     AwaitingConfirmations -- "Retransmit seen tx (planned)" --> AwaitingConfirmations
///     Created -- "No transactions seen for [time]" --> Timeout["Timed out"]
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct DepositStateMachine {
    pub(crate) operation_id: OperationId,
    pub(crate) state: DepositStates,
}

impl State for DepositStateMachine {
    type ModuleContext = WalletClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            DepositStates::Created(created_state) => {
                vec![
                    StateTransition::new(
                        await_created_btc_transaction_submitted(
                            context.clone(),
                            created_state.tweak_key,
                        ),
                        |_db, (btc_tx, out_idx), old_state| {
                            Box::pin(async move { transition_tx_seen(old_state, btc_tx, out_idx) })
                        },
                    ),
                    StateTransition::new(
                        await_deposit_address_timeout(created_state.timeout_at),
                        |_db, (), old_state| {
                            Box::pin(async move { transition_deposit_timeout(&old_state) })
                        },
                    ),
                ]
            }
            DepositStates::WaitingForConfirmations(waiting_state) => {
                let global_context = global_context.clone();
                vec![StateTransition::new(
                    await_btc_transaction_confirmed(
                        context.clone(),
                        global_context.clone(),
                        waiting_state.clone(),
                    ),
                    move |dbtx, txout_proof, old_state| {
                        Box::pin(transition_btc_tx_confirmed(
                            dbtx,
                            global_context.clone(),
                            old_state,
                            txout_proof,
                        ))
                    },
                )]
            }
            DepositStates::Claiming(_) | DepositStates::TimedOut(_) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

async fn await_created_btc_transaction_submitted(
    context: WalletClientContext,
    tweak: Keypair,
) -> (bitcoin::Transaction, u32) {
    let script = context
        .wallet_descriptor
        .tweak(&tweak.public_key(), &context.secp)
        .script_pubkey();
    loop {
        match context.rpc.watch_script_history(&script).await {
            Ok(()) => break,
            Err(e) => warn!("Error while awaiting btc tx submitting: {e}"),
        }
        sleep(TRANSACTION_STATUS_FETCH_INTERVAL).await;
    }
    for attempt in 0u32.. {
        sleep(cmp::min(
            TRANSACTION_STATUS_FETCH_INTERVAL * attempt,
            Duration::from_secs(60 * 15),
        ))
        .await;

        match context.rpc.get_script_history(&script).await {
            Ok(received) => {
                // TODO: fix
                if received.len() > 1 {
                    warn!("More than one transaction was sent to deposit address, only considering the first one");
                }

                if let Some((transaction, out_idx)) =
                    filter_onchain_deposit_outputs(received.into_iter(), &script).next()
                {
                    return (transaction, out_idx);
                }

                trace!("No transactions received yet for script {script:?}");
            }
            Err(e) => {
                warn!("Error fetching transaction history for {script:?}: {e}");
            }
        }
    }

    unreachable!()
}

fn transition_tx_seen(
    old_state: DepositStateMachine,
    btc_transaction: bitcoin::Transaction,
    out_idx: u32,
) -> DepositStateMachine {
    let DepositStateMachine {
        operation_id,
        state: old_state,
    } = old_state;

    match old_state {
        DepositStates::Created(created_state) => DepositStateMachine {
            operation_id,
            state: DepositStates::WaitingForConfirmations(WaitingForConfirmationsDepositState {
                tweak_key: created_state.tweak_key,
                btc_transaction,
                out_idx,
            }),
        },
        state => panic!("Invalid previous state: {state:?}"),
    }
}

async fn await_deposit_address_timeout(timeout_at: SystemTime) {
    if let Ok(time_until_deadline) = timeout_at.duration_since(fedimint_core::time::now()) {
        sleep(time_until_deadline).await;
    }
}

fn transition_deposit_timeout(old_state: &DepositStateMachine) -> DepositStateMachine {
    assert!(
        matches!(old_state.state, DepositStates::Created(_)),
        "Invalid previous state"
    );

    DepositStateMachine {
        operation_id: old_state.operation_id,
        state: DepositStates::TimedOut(TimedOutDepositState {}),
    }
}

#[instrument(skip_all, level = "debug")]
async fn await_btc_transaction_confirmed(
    context: WalletClientContext,
    global_context: DynGlobalClientContext,
    waiting_state: WaitingForConfirmationsDepositState,
) -> TxOutProof {
    loop {
        // TODO: make everything subscriptions
        // Wait for confirmation
        let consensus_block_count = match global_context
            .module_api()
            .fetch_consensus_block_count()
            .await
        {
            Ok(consensus_block_count) => consensus_block_count,
            Err(e) => {
                warn!("Failed to fetch consensus block count from federation: {e}");
                sleep(TRANSACTION_STATUS_FETCH_INTERVAL).await;
                continue;
            }
        };
        debug!(consensus_block_count, "Fetched consensus block count");

        let confirmation_block_count = match context
            .rpc
            .get_tx_block_height(&waiting_state.btc_transaction.compute_txid())
            .await
        {
            Ok(Some(confirmation_height)) => Some(confirmation_height + 1),
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to fetch confirmation height: {e:?}");
                sleep(TRANSACTION_STATUS_FETCH_INTERVAL).await;
                continue;
            }
        };

        debug!(
            ?confirmation_block_count,
            "Fetched confirmation block count"
        );

        if !confirmation_block_count.is_some_and(|confirmation_block_count| {
            consensus_block_count >= confirmation_block_count
        }) {
            trace!("Not confirmed yet, confirmation_block_count={confirmation_block_count:?}, consensus_block_count={consensus_block_count}");
            sleep(TRANSACTION_STATUS_FETCH_INTERVAL).await;
            continue;
        }

        // Get txout proof
        let txout_proof = match context
            .rpc
            .get_txout_proof(waiting_state.btc_transaction.compute_txid())
            .await
        {
            Ok(txout_proof) => txout_proof,
            Err(e) => {
                warn!("Failed to fetch transaction proof: {e:?}");
                sleep(TRANSACTION_STATUS_FETCH_INTERVAL).await;
                continue;
            }
        };

        debug!(proof_block_hash = ?txout_proof.block_header.block_hash(), "Generated merkle proof");

        return txout_proof;
    }
}

pub(crate) async fn transition_btc_tx_confirmed(
    dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
    global_context: DynGlobalClientContext,
    old_state: DepositStateMachine,
    txout_proof: TxOutProof,
) -> DepositStateMachine {
    let DepositStates::WaitingForConfirmations(awaiting_confirmation_state) = old_state.state
    else {
        panic!("Invalid previous state")
    };

    let pegin_proof = PegInProof::new(
        txout_proof,
        awaiting_confirmation_state.btc_transaction,
        awaiting_confirmation_state.out_idx,
        awaiting_confirmation_state.tweak_key.public_key(),
    )
    .expect("TODO: handle API returning faulty proofs");

    let amount = pegin_proof.tx_output().value.into();

    let wallet_input = WalletInput::new_v0(pegin_proof);

    let client_input = ClientInput::<WalletInput> {
        input: wallet_input,
        keys: vec![awaiting_confirmation_state.tweak_key],
        amount,
    };

    let (fm_txid, change) = global_context
        .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
        .await
        .expect("Cannot claim input, additional funding needed");

    DepositStateMachine {
        operation_id: old_state.operation_id,
        state: DepositStates::Claiming(ClaimingDepositState {
            transaction_id: fm_txid,
            change,
        }),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum DepositStates {
    Created(CreatedDepositState),
    WaitingForConfirmations(WaitingForConfirmationsDepositState),
    Claiming(ClaimingDepositState),
    TimedOut(TimedOutDepositState),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CreatedDepositState {
    pub(crate) tweak_key: Keypair,
    pub(crate) timeout_at: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct WaitingForConfirmationsDepositState {
    /// Key pair of which the public was used to tweak the federation's wallet
    /// descriptor. The secret key is later used to sign the fedimint claim
    /// transaction.
    tweak_key: Keypair,
    /// The bitcoin transaction is saved as soon as we see it so the transaction
    /// can be re-transmitted if it's evicted from the mempool.
    pub(crate) btc_transaction: bitcoin::Transaction,
    /// Index of the deposit output
    pub(crate) out_idx: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ClaimingDepositState {
    /// Fedimint transaction id in which the deposit is being claimed.
    pub(crate) transaction_id: TransactionId,
    pub(crate) change: Vec<OutPoint>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct TimedOutDepositState {}

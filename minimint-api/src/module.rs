use crate::db::batch::BatchTx;
use crate::{Amount, PeerId};
use async_trait::async_trait;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;

#[async_trait(?Send)]
pub trait FederationModule {
    type Error;
    type TxInput;
    type TxOutput;
    type TxOutputOutcome;
    type ConsensusItem;

    /// This module's contribution to the next consensus proposal
    async fn consensus_proposal<'a>(
        &'a self,
        rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem>;

    /// This function is called once before transaction processing starts. All module consensus
    /// items of this round are supplied as `consensus_items`. The batch will be committed to the
    /// database after all other modules ran `begin_consensus_epoch`, so the results are available
    /// when processing transactions.  
    async fn begin_consensus_epoch<'a>(
        &'a self,
        batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        rng: impl RngCore + CryptoRng + 'a,
    );

    /// Validate a transaction input before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_input(&self, input: &Self::TxInput) -> Result<Amount, Self::Error>;

    /// Try to spend a transaction input. On success all necessary updates will be part of the
    /// database `batch`. On failure (e.g. double spend) the batch is reset and the operation will
    /// take no effect.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transaction have been
    /// processed.
    fn apply_input<'a>(
        &'a self,
        batch: BatchTx<'a>,
        input: &'a Self::TxInput,
    ) -> Result<Amount, Self::Error>;

    /// Validate a transaction output before submitting it to the unconfirmed transaction pool. This
    /// function has no side effects and may be called at any time. False positives due to outdated
    /// database state are ok since they get filtered out after consensus has been reached on them
    /// and merely generate a warning.
    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error>;

    /// Try to create an output (e.g. issue coins, peg-out BTC, …). On success all necessary updates
    /// to the database will be part of the `batch`. On failure (e.g. double spend) the batch is
    /// reset and the operation will take no effect.
    ///
    /// The supplied `out_point` identifies the operation (e.g. a peg-out or coin issuance) and can
    /// be used to retrieve its outcome later using `output_status`.
    ///
    /// This function may only be called after `begin_consensus_epoch` and before
    /// `end_consensus_epoch`. Data is only written to the database once all transactions have been
    /// processed.
    fn apply_output<'a>(
        &'a self,
        batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: crate::transaction::OutPoint,
    ) -> Result<Amount, Self::Error>;

    /// This function is called once all transactions have been processed and changes were written
    /// to the database. This allows running finalization code before the next epoch.
    async fn end_consensus_epoch<'a>(
        &'a self,
        batch: BatchTx<'a>,
        rng: impl RngCore + CryptoRng + 'a,
    );

    /// Retrieve the current status of the output. Depending on the module this might contain data
    /// needed by the client to access funds or give an estimate of when funds will be available.
    /// Returns `None` if the output is unknown, **NOT** if it is just not ready yet.
    fn output_status(
        &self,
        out_point: crate::transaction::OutPoint,
    ) -> Option<Self::TxOutputOutcome>;
}

//! # Direct HTLC API
//!
//! This module exposes the outgoing contract of the `LNv2` module as a plain
//! HTLC between two clients of the same federation, without any Lightning
//! gateway involvement. This enables atomic swaps with counterparties outside
//! the federation's Lightning infrastructure, e.g. swaps with other chains or
//! currencies.
//!
//! The funder locks ecash to the counterparty's claim key via
//! [`LightningClientModule::create_htlc`]. The counterparty verifies the
//! funding via [`LightningClientModule::await_htlc_funded`] and resolves the
//! HTLC with the preimage via [`LightningClientModule::claim_htlc`], which
//! reveals the preimage to the funder via
//! [`LightningClientModule::await_htlc_resolution`]. A failed HTLC is either
//! cancelled cooperatively before its expiration with the counterparty's
//! forfeit signature via [`LightningClientModule::cancel_htlc`], or refunded
//! unilaterally after its expiration via
//! [`LightningClientModule::refund_htlc`].
//!
//! All coordination data - the contract, its funding outpoint and the forfeit
//! signature - is exchanged between the two parties out of band. The contract
//! expiration is measured in block count as tracked by the federation's
//! consensus.

use std::time::Duration;

use bitcoin::secp256k1;
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_core::core::OperationId;
use fedimint_core::module::{Amounts, CommonModuleInit};
use fedimint_core::task::sleep;
use fedimint_core::{Amount, OutPoint};
use fedimint_lnv2_common::contracts::{OutgoingContract, PaymentImage};
use fedimint_lnv2_common::{
    LightningCommonInit, LightningInput, LightningInputV0, LightningOutput, LightningOutputV0,
    OutgoingWitness, tweak,
};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SecretKey, ecdh};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::api::LightningFederationApi;
use crate::{LightningClientModule, LightningOperationMeta};

/// Metadata of an operation funding a direct HTLC via
/// [`LightningClientModule::create_htlc`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHtlcOperationMeta {
    /// The outpoint of the contract in the funding transaction; share this
    /// together with `contract` with the counterparty so they can verify and
    /// claim the HTLC.
    pub funding_outpoint: OutPoint,
    pub contract: OutgoingContract,
    pub change_outpoint_range: OutPointRange,
    pub custom_meta: Value,
}

/// Metadata of an operation spending a direct HTLC: a claim via
/// [`LightningClientModule::claim_htlc`], a refund via
/// [`LightningClientModule::refund_htlc`] or a cancellation via
/// [`LightningClientModule::cancel_htlc`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendHtlcOperationMeta {
    /// The outpoint the contract was funded at.
    pub htlc_outpoint: OutPoint,
    pub contract: OutgoingContract,
    pub change_outpoint_range: OutPointRange,
    pub custom_meta: Value,
}

/// Errors of the direct HTLC operations; see
/// [`LightningClientModule::create_htlc`].
#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum HtlcError {
    #[error("The amount must be greater than zero")]
    InvalidAmount,
    #[error("The expiration delta must be greater than zero")]
    InvalidExpirationDelta,
    #[error("Failed to request the consensus block count")]
    FailedToRequestBlockCount(String),
    #[error("Failed to submit the transaction")]
    FailedToSubmitTransaction(String),
    #[error("An operation for this contract action already exists")]
    DuplicateOperation(OperationId),
    #[error("The keypair does not match the contract's claim public key")]
    ClaimKeyMismatch,
    #[error("The preimage does not match the contract's payment image")]
    InvalidPreimage,
    #[error("The contract's refund key is not derived from our static module key")]
    RefundKeyMismatch,
    #[error("A different contract is funded at this outpoint")]
    ContractMismatch,
    #[error("No unresolved contract is funded at this outpoint")]
    ContractNotFound,
    #[error("The contract has already expired")]
    Expired,
    #[error("The contract only expires in {0} more blocks")]
    NotExpired(u64),
    #[error("The forfeit signature is invalid for this contract")]
    InvalidForfeitSignature,
    #[error("The federation returned an invalid preimage")]
    InvalidPreimageReturned,
    #[error("Failed to query the federation")]
    FederationApiError(String),
    #[error("No operation with this id exists")]
    UnknownOperation,
    #[error("The operation is not a direct HTLC operation")]
    NotAnHtlcOperation,
    #[error("The transaction was rejected: {0}")]
    TransactionRejected(String),
    #[error("Failed to mint the ecash: {0}")]
    FailedToMintEcash(String),
}

/// The parameters of a transaction spending a direct HTLC; see
/// [`LightningClientModule::spend_htlc`].
struct HtlcSpend {
    operation_id: OperationId,
    outpoint: OutPoint,
    contract: OutgoingContract,
    witness: OutgoingWitness,
    keypair: Keypair,
    make_meta: fn(SpendHtlcOperationMeta) -> LightningOperationMeta,
    custom_meta: Value,
}

impl LightningClientModule {
    /// Fund a direct HTLC: an outgoing contract of `amount` locked to the
    /// counterparty's `claim_pk`, without any gateway involvement. The
    /// counterparty can claim the contract with the preimage of
    /// `payment_image` via [`Self::claim_htlc`] until `expiration_delta`
    /// blocks from now; afterwards we can reclaim it via
    /// [`Self::refund_htlc`], or earlier via [`Self::cancel_htlc`] if the
    /// counterparty provides a forfeit signature.
    ///
    /// Returns the contract and the outpoint it is funded at; share both with
    /// the counterparty so they can verify the funding via
    /// [`Self::await_htlc_funded`] and claim the contract. Await the
    /// acceptance of the funding transaction via
    /// [`Self::await_htlc_operation_settled`] and the counterparty's claim
    /// via [`Self::await_htlc_resolution`], which yields the preimage.
    ///
    /// The contract's refund key is derived from our static module key via
    /// the ephemeral key committed in the contract, so refunding and
    /// cancelling only require the contract itself, not this operation's
    /// local state.
    pub async fn create_htlc(
        &self,
        amount: Amount,
        payment_image: PaymentImage,
        claim_pk: PublicKey,
        expiration_delta: u64,
        custom_meta: Value,
    ) -> Result<(OperationId, OutPoint, OutgoingContract), HtlcError> {
        if amount == Amount::ZERO {
            return Err(HtlcError::InvalidAmount);
        }

        if expiration_delta == 0 {
            return Err(HtlcError::InvalidExpirationDelta);
        }

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .map_err(|e| HtlcError::FailedToRequestBlockCount(e.to_string()))?;

        let (ephemeral_tweak, ephemeral_pk) = tweak::generate(self.keypair.public_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak)
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        let contract = OutgoingContract {
            payment_image,
            amount,
            expiration: consensus_block_count + expiration_delta,
            claim_pk,
            refund_pk: refund_keypair.public_key(),
            ephemeral_pk,
        };

        let operation_id = OperationId::from_encodable(&("lnv2-htlc-create", contract.clone()));

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Outgoing(contract.clone())),
            amounts: Amounts::new_bitcoin(contract.amount),
        };

        let client_outputs = self
            .client_ctx
            .make_client_outputs(ClientOutputBundle::new_no_sm(vec![client_output]));

        let transaction = TransactionBuilder::new().with_outputs(client_outputs);

        let contract_clone = contract.clone();

        let change_range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                move |change_outpoint_range: OutPointRange| {
                    LightningOperationMeta::CreateHtlc(CreateHtlcOperationMeta {
                        // The contract is the only output submitted before the
                        // change, which is always appended after it.
                        funding_outpoint: OutPoint {
                            txid: change_outpoint_range.txid,
                            out_idx: 0,
                        },
                        contract: contract_clone.clone(),
                        change_outpoint_range,
                        custom_meta: custom_meta.clone(),
                    })
                },
                transaction,
            )
            .await
            .map_err(|e| HtlcError::FailedToSubmitTransaction(e.to_string()))?;

        let funding_outpoint = OutPoint {
            txid: change_range.txid,
            out_idx: 0,
        };

        Ok((operation_id, funding_outpoint, contract))
    }

    /// Claim a direct HTLC funded at `outpoint` with the preimage of its
    /// payment image; the ecash is issued to our wallet. The claiming
    /// transaction has to be signed by the contract's claim key, hence the
    /// `claim_keypair`.
    ///
    /// Since the preimage becomes public with the claiming transaction the
    /// caller has to ensure sufficient time until the contract's expiration
    /// remains; this method only rejects contracts that have already expired.
    /// Await the issuance of the ecash via
    /// [`Self::await_htlc_operation_settled`].
    pub async fn claim_htlc(
        &self,
        outpoint: OutPoint,
        contract: OutgoingContract,
        claim_keypair: Keypair,
        preimage: [u8; 32],
        custom_meta: Value,
    ) -> Result<OperationId, HtlcError> {
        if claim_keypair.public_key() != contract.claim_pk {
            return Err(HtlcError::ClaimKeyMismatch);
        }

        if !contract.verify_preimage(&preimage) {
            return Err(HtlcError::InvalidPreimage);
        }

        let (contract_id, remaining_blocks) = self
            .module_api
            .outgoing_contract_expiration(outpoint)
            .await
            .map_err(|e| HtlcError::FederationApiError(e.to_string()))?
            .ok_or(HtlcError::ContractNotFound)?;

        if contract_id != contract.contract_id() {
            return Err(HtlcError::ContractMismatch);
        }

        if remaining_blocks == 0 {
            return Err(HtlcError::Expired);
        }

        self.spend_htlc(HtlcSpend {
            operation_id: OperationId::from_encodable(&("lnv2-htlc-claim", outpoint)),
            outpoint,
            contract,
            witness: OutgoingWitness::Claim(preimage),
            keypair: claim_keypair,
            make_meta: LightningOperationMeta::ClaimHtlc,
            custom_meta,
        })
        .await
    }

    /// Refund a direct HTLC we created via [`Self::create_htlc`] after its
    /// expiration; the ecash is issued back to our wallet. Await the issuance
    /// via [`Self::await_htlc_operation_settled`].
    pub async fn refund_htlc(
        &self,
        outpoint: OutPoint,
        contract: OutgoingContract,
        custom_meta: Value,
    ) -> Result<OperationId, HtlcError> {
        let refund_keypair = self
            .recover_htlc_refund_keypair(&contract)
            .ok_or(HtlcError::RefundKeyMismatch)?;

        let consensus_block_count = self
            .module_api
            .consensus_block_count()
            .await
            .map_err(|e| HtlcError::FailedToRequestBlockCount(e.to_string()))?;

        if consensus_block_count < contract.expiration {
            return Err(HtlcError::NotExpired(
                contract.expiration - consensus_block_count,
            ));
        }

        self.spend_htlc(HtlcSpend {
            operation_id: OperationId::from_encodable(&("lnv2-htlc-refund", outpoint)),
            outpoint,
            contract,
            witness: OutgoingWitness::Refund,
            keypair: refund_keypair,
            make_meta: LightningOperationMeta::RefundHtlc,
            custom_meta,
        })
        .await
    }

    /// Cancel a direct HTLC we created via [`Self::create_htlc`] before its
    /// expiration using the counterparty's `forfeit_signature`, created via
    /// [`Self::create_htlc_forfeit_signature`]; the ecash is issued back to
    /// our wallet. Await the issuance via
    /// [`Self::await_htlc_operation_settled`].
    pub async fn cancel_htlc(
        &self,
        outpoint: OutPoint,
        contract: OutgoingContract,
        forfeit_signature: Signature,
        custom_meta: Value,
    ) -> Result<OperationId, HtlcError> {
        if !contract.verify_forfeit_signature(&forfeit_signature) {
            return Err(HtlcError::InvalidForfeitSignature);
        }

        let refund_keypair = self
            .recover_htlc_refund_keypair(&contract)
            .ok_or(HtlcError::RefundKeyMismatch)?;

        self.spend_htlc(HtlcSpend {
            operation_id: OperationId::from_encodable(&("lnv2-htlc-cancel", outpoint)),
            outpoint,
            contract,
            witness: OutgoingWitness::Cancel(forfeit_signature),
            keypair: refund_keypair,
            make_meta: LightningOperationMeta::CancelHtlc,
            custom_meta,
        })
        .await
    }

    /// Create a forfeit signature for a direct HTLC locked to our
    /// `claim_keypair`, which allows its funder to reclaim the contract
    /// before its expiration via [`Self::cancel_htlc`]. This is how the
    /// claiming side fails an HTLC cooperatively; it is a pure offline
    /// operation.
    pub fn create_htlc_forfeit_signature(
        contract: &OutgoingContract,
        claim_keypair: &Keypair,
    ) -> Result<Signature, HtlcError> {
        if claim_keypair.public_key() != contract.claim_pk {
            return Err(HtlcError::ClaimKeyMismatch);
        }

        Ok(claim_keypair.sign_schnorr(contract.forfeit_message()))
    }

    /// Wait until the given contract is funded at `outpoint` and return the
    /// number of blocks remaining until its expiration. This is how the
    /// claiming side verifies the funder's claim that the HTLC exists before
    /// taking any action of its own, e.g. sending funds on another chain.
    ///
    /// This method polls the federation indefinitely, so callers should
    /// enforce their own timeout; note that it will also never resolve if the
    /// contract has already been claimed, refunded or cancelled again.
    pub async fn await_htlc_funded(
        &self,
        outpoint: OutPoint,
        contract: &OutgoingContract,
    ) -> Result<u64, HtlcError> {
        loop {
            match self.module_api.outgoing_contract_expiration(outpoint).await {
                Ok(Some((contract_id, remaining_blocks))) => {
                    if contract_id != contract.contract_id() {
                        return Err(HtlcError::ContractMismatch);
                    }

                    return Ok(remaining_blocks);
                }
                Ok(None) | Err(..) => sleep(Duration::from_secs(1)).await,
            }
        }
    }

    /// Wait until the direct HTLC funded at `outpoint` is either claimed, in
    /// which case the preimage is returned, or expired unclaimed, in which
    /// case `None` is returned and the funder can safely refund the contract
    /// via [`Self::refund_htlc`].
    pub async fn await_htlc_resolution(
        &self,
        outpoint: OutPoint,
        contract: &OutgoingContract,
    ) -> Result<Option<[u8; 32]>, HtlcError> {
        match self
            .module_api
            .await_preimage(outpoint, contract.expiration)
            .await
        {
            Some(preimage) => {
                if contract.verify_preimage(&preimage) {
                    Ok(Some(preimage))
                } else {
                    Err(HtlcError::InvalidPreimageReturned)
                }
            }
            None => Ok(None),
        }
    }

    /// Wait until the transaction of a direct HTLC operation is accepted by
    /// the federation and any ecash it issues has been minted.
    pub async fn await_htlc_operation_settled(
        &self,
        operation_id: OperationId,
    ) -> Result<(), HtlcError> {
        let operation = self
            .client_ctx
            .get_operation(operation_id)
            .await
            .map_err(|_| HtlcError::UnknownOperation)?;

        if operation.operation_module_kind() != LightningCommonInit::KIND.as_str() {
            return Err(HtlcError::NotAnHtlcOperation);
        }

        let change_outpoint_range = match operation.meta::<LightningOperationMeta>() {
            LightningOperationMeta::CreateHtlc(meta) => meta.change_outpoint_range,
            LightningOperationMeta::ClaimHtlc(meta)
            | LightningOperationMeta::RefundHtlc(meta)
            | LightningOperationMeta::CancelHtlc(meta) => meta.change_outpoint_range,
            LightningOperationMeta::Send(..)
            | LightningOperationMeta::Receive(..)
            | LightningOperationMeta::LnurlReceive(..) => {
                return Err(HtlcError::NotAnHtlcOperation);
            }
        };

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(change_outpoint_range.txid)
            .await
            .map_err(HtlcError::TransactionRejected)?;

        self.client_ctx
            .await_primary_module_outputs(operation_id, change_outpoint_range.into_iter().collect())
            .await
            .map_err(|e| HtlcError::FailedToMintEcash(e.to_string()))?;

        Ok(())
    }

    /// Submit a transaction spending a direct HTLC and record it under a new
    /// operation.
    async fn spend_htlc(&self, spend: HtlcSpend) -> Result<OperationId, HtlcError> {
        let HtlcSpend {
            operation_id,
            outpoint,
            contract,
            witness,
            keypair,
            make_meta,
            custom_meta,
        } = spend;

        if self.client_ctx.operation_exists(operation_id).await {
            return Err(HtlcError::DuplicateOperation(operation_id));
        }

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Outgoing(outpoint, witness)),
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![keypair],
        };

        let client_inputs = self
            .client_ctx
            .make_client_inputs(ClientInputBundle::new_no_sm(vec![client_input]));

        let transaction = TransactionBuilder::new().with_inputs(client_inputs);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                move |change_outpoint_range: OutPointRange| {
                    make_meta(SpendHtlcOperationMeta {
                        htlc_outpoint: outpoint,
                        contract: contract.clone(),
                        change_outpoint_range,
                        custom_meta: custom_meta.clone(),
                    })
                },
                transaction,
            )
            .await
            .map_err(|e| HtlcError::FailedToSubmitTransaction(e.to_string()))?;

        Ok(operation_id)
    }

    /// Recover the refund keypair of a direct HTLC created by this client
    /// from the contract's ephemeral key and our static module key.
    fn recover_htlc_refund_keypair(&self, contract: &OutgoingContract) -> Option<Keypair> {
        let ephemeral_tweak =
            ecdh::SharedSecret::new(&contract.ephemeral_pk, &self.keypair.secret_key());

        let refund_keypair = SecretKey::from_slice(&ephemeral_tweak.secret_bytes())
            .expect("32 bytes, within curve order")
            .keypair(secp256k1::SECP256K1);

        (refund_keypair.public_key() == contract.refund_pk).then_some(refund_keypair)
    }
}

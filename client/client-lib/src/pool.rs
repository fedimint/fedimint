use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::KeyPair;
use fedimint_api::core::LEGACY_HARDCODED_INSTANCE_ID_POOL;
use fedimint_api::{encoding::Encodable, module::TransactionItemAmount, Amount};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use secp256k1::Secp256k1;
use stabilitypool::api::State;
use stabilitypool::config::PoolConfigClient;
use stabilitypool::{
    api, AccountDeposit, AccountWithdrawal, Action, ActionProposed, ActionStaged, EpochOutcome,
    ProviderBid, SeekerAction, SignedAction,
};

use crate::api::{erased_no_param, erased_single_param, FederationApiExt, FederationResult};
use crate::utils::ClientContext;
use crate::Result;

pub struct PoolClient {
    pub secret: DerivableSecret,
    pub config: PoolConfigClient,
    pub context: Arc<ClientContext>,
}

impl PoolClient {
    pub fn account_key(&self) -> KeyPair {
        self.secret
            .child_key(ChildId(0))
            .to_secp_key(&Secp256k1::signing_only())
    }

    pub async fn balance(&self) -> FederationResult<api::BalanceResponse> {
        self.context
            .api
            .request_current_consensus(
                format!("/module/{}/account", LEGACY_HARDCODED_INSTANCE_ID_POOL),
                erased_single_param(&self.account_key().x_only_public_key().0),
            )
            .await
    }

    pub async fn epoch_outcome(&self, epoch_id: u64) -> FederationResult<EpochOutcome> {
        self.context
            .api
            .request_current_consensus(
                format!("/module/{}/epoch", LEGACY_HARDCODED_INSTANCE_ID_POOL),
                erased_single_param(&epoch_id),
            )
            .await
    }

    pub async fn staging_epoch(&self) -> FederationResult<u64> {
        self.context
            .api
            .request_current_consensus(
                format!("/module/{}/epoch_next", LEGACY_HARDCODED_INSTANCE_ID_POOL),
                erased_no_param(),
            )
            .await
    }

    pub fn input_amount(&self, input: &AccountWithdrawal) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: input.amount,
            fee: Amount::ZERO, // TODO: do this properly
        }
    }

    pub fn output_amount(&self, output: &AccountDeposit) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.amount,
            fee: Amount::ZERO, // TODO do this properly
        }
    }

    async fn create_signed_acton<T: Encodable>(
        &self,
        unsigned_action: T,
    ) -> Result<SignedAction<T>> {
        let kp = self.account_key();
        let sequence = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let action = Action {
            epoch_id: self.staging_epoch().await?,
            sequence,
            account_id: kp.x_only_public_key().0,
            body: unsigned_action,
        };

        let digest =
            bitcoin::hashes::sha256::Hash::hash(&action.consensus_encode_to_vec().unwrap());
        let signature = Secp256k1::signing_only().sign_schnorr(&digest.into(), &kp);
        let signed_action = SignedAction { signature, action };
        Ok(signed_action)
    }

    pub async fn propose_seeker_action(&self, action: SeekerAction) -> FederationResult<()> {
        let signed_action: ActionProposed = self
            .create_signed_acton(action)
            .await
            .expect("TODO: signing should not fail")
            .into();
        self.context
            .api
            .request_current_consensus(
                format!(
                    "/module/{}/action_propose",
                    LEGACY_HARDCODED_INSTANCE_ID_POOL
                ),
                erased_single_param(&signed_action),
            )
            .await
    }

    pub async fn propose_provider_action(&self, action: ProviderBid) -> FederationResult<()> {
        let signed_action: ActionProposed = self
            .create_signed_acton(action)
            .await
            .expect("TODO: signing should not fail")
            .into();
        self.context
            .api
            .request_current_consensus(
                format!(
                    "/module/{}/action_propose",
                    LEGACY_HARDCODED_INSTANCE_ID_POOL
                ),
                erased_single_param(&signed_action),
            )
            .await
    }

    pub async fn staged_action(&self) -> FederationResult<ActionStaged> {
        self.context
            .api
            .request_current_consensus(
                format!("/module/{}/action", LEGACY_HARDCODED_INSTANCE_ID_POOL),
                erased_single_param(&self.account_key().x_only_public_key().0),
            )
            .await
    }

    pub async fn state(&self) -> FederationResult<State> {
        self.context
            .api
            .request_current_consensus(
                format!("/module/{}/state", LEGACY_HARDCODED_INSTANCE_ID_POOL),
                erased_no_param(),
            )
            .await
    }
}

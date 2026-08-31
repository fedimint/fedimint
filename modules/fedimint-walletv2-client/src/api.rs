use std::collections::BTreeMap;

use anyhow::anyhow;
use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi,
};
use fedimint_api_client::query::ThresholdAgreement;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    OUTPUT_INFO_SLICE_ENDPOINT, PENDING_OUTPUTS_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT,
    RECEIVE_FEE_ENDPOINT, SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
};
use fedimint_walletv2_common::{
    FederationWallet, OutputInfo, PendingOutput, PendingOutputs, TxInfo,
};

/// Renders each peer's fee answer so a divergence error names the odd one out.
fn describe_fee_quotes(quotes: &BTreeMap<PeerId, Option<bitcoin::Amount>>) -> String {
    quotes
        .iter()
        .map(|(peer, fee)| match fee {
            Some(fee) => format!("peer {peer}: {} sats", fee.to_sat()),
            None => format!("peer {peer}: no quote"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[apply(async_trait_maybe_send!)]
pub trait WalletFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn consensus_feerate(&self) -> FederationResult<Option<u64>>;

    async fn federation_wallet(&self) -> FederationResult<Option<FederationWallet>>;

    async fn send_fee(&self) -> FederationResult<Option<bitcoin::Amount>>;

    async fn receive_fee(&self) -> FederationResult<Option<bitcoin::Amount>>;

    async fn pending_tx_chain(&self) -> FederationResult<Vec<TxInfo>>;

    async fn tx_chain(&self) -> FederationResult<Vec<TxInfo>>;

    async fn output_info_slice(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> FederationResult<Vec<OutputInfo>>;

    async fn tx_id(&self, outpoint: OutPoint) -> Option<bitcoin::Txid>;

    /// Fetches the guardians' local views of mined but not yet final receive
    /// outputs, merged into a single view.
    ///
    /// This is advisory data used to display peg-in progress. It is
    /// deliberately not requested via threshold consensus: guardians observe
    /// the chain tip independently and will legitimately disagree by a block,
    /// so a consensus request would simply never resolve. Peers that error,
    /// including guardians too old to know the endpoint, are skipped.
    async fn pending_outputs(&self) -> PendingOutputs;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> WalletFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn consensus_feerate(&self) -> FederationResult<Option<u64>> {
        self.request_current_consensus(
            CONSENSUS_FEERATE_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn federation_wallet(&self) -> FederationResult<Option<FederationWallet>> {
        self.request_current_consensus(
            FEDERATION_WALLET_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn send_fee(&self) -> FederationResult<Option<bitcoin::Amount>> {
        // Deliberately not `request_current_consensus`; see the same reasoning in
        // wallet v1's `fetch_peg_out_fees`. walletv2 is if anything more exposed:
        // this single amount folds together the consensus feerate, a floor that
        // doubles with every pending federation transaction, and the fees already
        // paid by that pending stack, so any one of them diverging is enough to
        // stop a threshold ever agreeing and hang the caller forever.
        let quotes = match self
            .request_with_strategy(
                ThresholdAgreement::new(self.all_peers().to_num_peers()),
                SEND_FEE_ENDPOINT.to_string(),
                ApiRequestErased::new(()),
            )
            .await?
        {
            Ok(fee) => return Ok(fee),
            Err(quotes) => quotes,
        };

        Err(FederationError::general(
            SEND_FEE_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
            anyhow!(
                "Guardians disagree on the onchain send fee ({}). The fee is \
                 consensus state, so a guardian returning a different value has \
                 diverged - because its Bitcoin backend is lagging, or because its \
                 view of the pending transaction stack differs. The same fee \
                 validates the send, so it cannot be accepted until they agree.",
                describe_fee_quotes(&quotes)
            ),
        ))
    }

    async fn receive_fee(&self) -> FederationResult<Option<bitcoin::Amount>> {
        // Same reasoning as `send_fee`. The caller here is the background
        // output-scanner, which loops with a `warn!` and a sleep, so returning
        // an error is how this waits for consensus *visibly*: it keeps retrying
        // for as long as the divergence lasts and resumes on its own, instead of
        // wedging the scanner inside a request that never returns.
        let quotes = match self
            .request_with_strategy(
                ThresholdAgreement::new(self.all_peers().to_num_peers()),
                RECEIVE_FEE_ENDPOINT.to_string(),
                ApiRequestErased::new(()),
            )
            .await?
        {
            Ok(fee) => return Ok(fee),
            Err(quotes) => quotes,
        };

        Err(FederationError::general(
            RECEIVE_FEE_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
            anyhow!(
                "Guardians disagree on the onchain receive fee ({}). The fee is \
                 consensus state, so a guardian returning a different value has \
                 diverged - because its Bitcoin backend is lagging, or because its \
                 view of the pending transaction stack differs. The same fee \
                 validates the claim, so it cannot be accepted until they agree.",
                describe_fee_quotes(&quotes)
            ),
        ))
    }

    async fn pending_tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.request_current_consensus(
            PENDING_TRANSACTION_CHAIN_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn tx_chain(&self) -> FederationResult<Vec<TxInfo>> {
        self.request_current_consensus(
            TRANSACTION_CHAIN_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    async fn output_info_slice(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> FederationResult<Vec<OutputInfo>> {
        self.request_current_consensus(
            OUTPUT_INFO_SLICE_ENDPOINT.to_string(),
            ApiRequestErased::new((start_index, end_index)),
        )
        .await
    }

    async fn tx_id(&self, outpoint: OutPoint) -> Option<bitcoin::Txid> {
        self.request_current_consensus_retry(
            TRANSACTION_ID_ENDPOINT.to_string(),
            ApiRequestErased::new(outpoint),
        )
        .await
    }

    async fn pending_outputs(&self) -> PendingOutputs {
        let responses = futures::future::join_all(self.all_peers().iter().map(|peer| async move {
            self.request_single_peer::<PendingOutputs>(
                PENDING_OUTPUTS_ENDPOINT.to_string(),
                ApiRequestErased::new(()),
                *peer,
            )
            .await
        }))
        .await;

        let mut block_count = 0;
        let mut outputs: BTreeMap<bitcoin::OutPoint, PendingOutput> = BTreeMap::new();

        for response in responses.into_iter().flatten() {
            // Take the highest tip any guardian reports so that a peer lagging
            // by a block does not walk back a confirmation count we already
            // showed the user.
            block_count = block_count.max(response.block_count);

            for output in response.outputs {
                // Guardians can disagree on the height of an outpoint across a
                // reorg. Keep the deepest height, which yields the lower
                // confirmation count, so progress is never overstated.
                outputs
                    .entry(output.outpoint)
                    .and_modify(|existing| {
                        if output.height > existing.height {
                            existing.height = output.height;
                        }
                    })
                    .or_insert(output);
            }
        }

        PendingOutputs {
            block_count,
            outputs: outputs.into_values().collect(),
        }
    }
}

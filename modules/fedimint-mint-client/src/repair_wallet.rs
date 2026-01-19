use std::collections::BTreeMap;

use fedimint_api_client::api::DynModuleApi;
use fedimint_core::db::{IReadDatabaseTransactionOpsTyped, IWriteDatabaseTransactionOpsTyped};
use fedimint_core::util::backoff_util::aggressive_backoff;
use fedimint_core::util::retry;
use fedimint_core::{Amount, TieredCounts};
use futures::{StreamExt, TryStreamExt, stream};

use crate::api::MintFederationApi;
use crate::client_db::{
    NextECashNoteIndexKey, NextECashNoteIndexKeyPrefix, NoteKey, NoteKeyPrefix,
};
use crate::output::NoteIssuanceRequest;
use crate::{MintClientModule, NoteIndex};

const CHECK_PARALLELISM: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct RepairSummary {
    /// Number of e-cash notes that were found to be spent and removed from the
    /// wallet per denomination
    pub spent_notes: TieredCounts,
    /// Denomination of which e-cash nonces were found to be used already and
    /// were skipped
    ///
    /// Note: if this is non-empty the correct approach is doing a full
    /// from-scratch recovery, otherwise we might not be aware of unspent notes
    /// issued to us.
    pub used_indices: TieredCounts,
}

impl MintClientModule {
    /// Attempts to fix inconsistent wallet states. **Breaks privacy guarantees
    /// and is destructive!**
    ///
    /// Invalid states that are fixable this way:
    ///   * Already-spent e-cash being in the wallet
    ///   * E-cash nonces that would be used to issue new notes already being
    ///     used
    ///
    /// When invalid notes are found, they are removed from the wallet. Make
    /// sure that the user has a backup of their seed before running this
    /// function.
    pub async fn try_repair_wallet(&self, gap_limit: u64) -> anyhow::Result<RepairSummary> {
        let mut summary = RepairSummary::default();

        let module_api = self.client_ctx.module_api();
        let mut dbtx = self.client_ctx.module_db().begin_write_transaction().await;

        // First check if any of our notes are already spent and remove them
        let spent_notes: Vec<NoteKey> = dbtx
            .find_by_prefix_sorted_descending(&NoteKeyPrefix)
            .await
            .map(|(key, _)| {
                let module_api_inner = module_api.clone();
                async move {
                    let spent = retry("fetch e-cash spentness", aggressive_backoff(), || async {
                        Ok(module_api_inner.check_note_spent(key.nonce).await?)
                    })
                    .await?;
                    anyhow::Ok(if spent { Some(key) } else { None })
                }
            })
            .buffer_unordered(CHECK_PARALLELISM)
            .try_filter_map(|result| async move { Ok(result) })
            .try_collect()
            .await?;

        for note_key in spent_notes {
            summary.spent_notes.inc(note_key.amount, 1);
            dbtx.remove_entry(&note_key).await;
        }

        let next_indices: BTreeMap<_, _> = {
            let mut db_next_indexes = dbtx
                .find_by_prefix_sorted_descending(&NextECashNoteIndexKeyPrefix)
                .await
                .map(|(key, idx)| (key.0, idx))
                .collect::<BTreeMap<_, _>>()
                .await;

            self.cfg
                .tbs_pks
                .tiers()
                .map(|&denomination| {
                    (
                        denomination,
                        db_next_indexes.remove(&denomination).unwrap_or_default(),
                    )
                })
                .collect()
        };

        // Next check if any of the indices for issuing new notes are already used
        let used_nonces = stream::iter(next_indices.into_iter())
            .map(|(amount, original_next_index)| {
                let module_api_inner = module_api.clone();
                async move {
                    let mut next_index = original_next_index;
                    let maybe_advanced_index = loop {
                        let maybe_nonce_gap = self
                            .gap_till_next_nonce_used(
                                &module_api_inner,
                                amount,
                                next_index,
                                gap_limit,
                            )
                            .await?;

                        if let Some(gap) = maybe_nonce_gap {
                            // If the nonce was already used, try again with the next index
                            next_index += gap + 1;
                        } else if original_next_index == next_index {
                            // If the initial nonce wasn't used we are good, nothing to be done
                            break None;
                        } else {
                            // If the initial nonce was used but we found an unused one by now,
                            // report the used index
                            break Some((amount, next_index));
                        }
                    };

                    Result::<_, anyhow::Error>::Ok(maybe_advanced_index)
                }
            })
            .buffer_unordered(CHECK_PARALLELISM)
            .try_filter_map(|advanced_index| async move { Ok(advanced_index) })
            .try_collect::<Vec<_>>()
            .await?;

        for (amount, next_index) in used_nonces {
            let old_index = dbtx
                .insert_entry(&NextECashNoteIndexKey(amount), &next_index)
                .await
                .unwrap_or_default();
            summary
                .used_indices
                .inc(amount, (next_index - old_index) as usize);
        }

        dbtx.commit_tx().await;
        Ok(summary)
    }

    /// Checks up to `gap_limit` nonces starting from `base_index` for having
    /// being used already.
    ///
    /// If the nonce at `base_index` is used, returns `Some(0)`, if it's unused
    /// returns `None`. If there's an unused nonce and then a used one returns
    /// `Some(1)`.
    async fn gap_till_next_nonce_used(
        &self,
        module_api: &DynModuleApi,
        amount: Amount,
        base_index: u64,
        gap_limit: u64,
    ) -> anyhow::Result<Option<u64>> {
        for gap in 0..gap_limit {
            let idx = base_index + gap;
            let note_secret = Self::new_note_secret_static(&self.secret, amount, NoteIndex(idx));
            let (_, blind_nonce) = NoteIssuanceRequest::new(&self.secp, &note_secret);
            let nonce_used = retry(
                "checking if blind nonce was already used",
                aggressive_backoff(),
                || async { Ok(module_api.check_blind_nonce_used(blind_nonce).await?) },
            )
            .await?;
            if nonce_used {
                return Ok(Some(gap));
            }
        }
        Ok(None)
    }
}

//! Integration test suite
//!
//! This crate contains integration tests that work by creating
//! per-test federation, ln-gateway and driving bitcoind and lightning
//! nodes to exercise certain behaviors on it.
//!
//! We run them in two modes:
//!
//! * With mocks - fake implementations of Lightning and Bitcoin node that only
//!   simulate the real behavior. These are instantiated per test.
//! * Without mocks - against real bitcoind and lightningd.
//!
//! When running against real bitcoind, the other tests might create
//! new blocks and transactions, so the tests can't expect to have
//! exclusive control over it. When it is really necessary, `lock_exclusive`
//! can be used to achieve it, but that makes the given test run serially
//! is thus undesirable.
mod fixtures;

use anyhow::Result;
use assert_matches::assert_matches;
use bitcoin::Amount;
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_core::api::{GlobalFederationApi, WsFederationApi};
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::task::TaskGroup;
use fedimint_core::{msats, sats};
use fedimint_server::epoch::ConsensusItem;
use fedimint_wallet_server::common::{PegOutFees, Rbf};
use futures::future::{join_all, Either};
use serde::{Deserialize, Serialize};

use crate::fixtures::{peers, test};

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_outs_are_rejected_if_fees_are_too_low() -> Result<()> {
    test(2, |fed, user, bitcoin| async move {
        let peg_out_amount = Amount::from_sat(1000);
        let peg_out_address = bitcoin.get_new_address().await;

        fed.mine_and_mint(&*user, &*bitcoin, sats(3000)).await;
        let mut peg_out = user
            .fetch_peg_out_fees(peg_out_amount, peg_out_address.clone())
            .await
            .unwrap();

        // Lower rate below FeeConsensus
        peg_out.fees.fee_rate.sats_per_kvb = 10;
        // TODO: return a better error message to clients
        assert!(user.submit_peg_out(peg_out).await.is_err());
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_outs_support_rbf() -> Result<()> {
    test(2, |fed, user, bitcoin| async move {
        // Need lock to keep tx in mempool from getting mined
        let bitcoin = bitcoin.lock_exclusive().await;
        let address = bitcoin.get_new_address().await;

        fed.mine_and_mint(&*user, &*bitcoin, sats(5000)).await;
        let (fees, out_point) = user.peg_out(1000, &address);
        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;

        let txid = user.await_peg_out_txid(out_point).await.unwrap();
        assert_eq!(
            bitcoin.get_mempool_tx_fee(&txid).await,
            fees.amount().into()
        );

        // RBF by increasing sats per kvb by 1000
        let rbf = Rbf {
            fees: PegOutFees::new(1000, fees.total_weight),
            txid,
        };
        let out_point = user.rbf_peg_out_tx(rbf.clone()).await.unwrap();
        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;
        let txid = user.await_peg_out_txid(out_point).await.unwrap();

        assert_eq!(
            bitcoin.get_mempool_tx_fee(&txid).await,
            (fees.amount() + rbf.fees.amount()).into()
        );

        assert_eq!(
            bitcoin.mine_block_and_get_received(&address).await,
            sats(1000)
        );
        bitcoin
            .mine_blocks(fed.wallet.consensus.finality_delay as u64)
            .await;
        fed.run_consensus_epochs(1).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_ins_that_are_unconfirmed_are_rejected() -> Result<()> {
    test(2, |_fed, user, bitcoin| async move {
        let peg_in_address = user.get_new_peg_in_address().await;
        let (proof, tx) = bitcoin
            .send_and_mine_block(&peg_in_address, Amount::from_sat(10000))
            .await;
        let result = user.submit_peg_in(proof, tx).await;

        // TODO make return error more useful
        assert!(result.is_err());
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_outs_must_wait_for_available_utxos() -> Result<()> {
    test(2, |fed, user, bitcoin| async move {
        // at least one epoch needed to establish fees
        bitcoin.prepare_funding_wallet().await;
        fed.run_consensus_epochs(1).await;

        // This test has many assumptions about bitcoin L1 blocks
        // and FM epochs, so we just lock the node
        let bitcoin = bitcoin.lock_exclusive().await;

        let address1 = bitcoin.get_new_address().await;
        let address2 = bitcoin.get_new_address().await;

        fed.mine_and_mint(&*user, &*bitcoin, sats(5000)).await;
        user.peg_out(1000, &address1);

        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;
        assert_eq!(
            bitcoin.mine_block_and_get_received(&address1).await,
            sats(1000)
        );

        // The change UTXO is still finalizing
        let response = user.fetch_peg_out_fees(Amount::from_sat(2000), address2.clone());
        assert_matches!(response.await, Err(_));

        bitcoin.mine_blocks(100).await;
        fed.run_consensus_epochs(1).await;
        user.peg_out(2000, &address2);
        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;
        assert_eq!(
            bitcoin.mine_block_and_get_received(&address2).await,
            sats(2000)
        );
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_exchanged_directly_between_users() -> Result<()> {
    test(4, |fed, user_send, bitcoin| async move {
        let user_receive = user_send.new_client_with_peers(peers(&[0, 1, 2]));

        fed.mine_and_mint(&*user_send, &*bitcoin, sats(5000)).await;
        assert_eq!(user_send.ecash_total(), sats(5000));
        assert_eq!(user_receive.ecash_total(), sats(0));

        let ecash = fed.spend_ecash(&*user_send, sats(3500)).await;
        user_receive.reissue(ecash).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        assert_eq!(user_send.ecash_total(), sats(1500));
        assert_eq!(user_receive.ecash_total(), sats(3500));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

// this test had to be removed to switch to aleph bft and should be ported to
// the new testing framework.
#[tokio::test(flavor = "multi_thread")]
async fn ecash_cannot_double_spent_with_different_nodes() -> Result<()> {
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_in_wallet_can_sent_through_a_tx() -> Result<()> {
    test(2, |fed, user_send, bitcoin| async move {
        let dummy_user = user_send.new_client_with_peers(peers(&[0]));
        let user_receive = user_send.new_client_with_peers(peers(&[0]));

        user_send.set_notes_per_denomination(1).await;
        user_receive.set_notes_per_denomination(1).await;

        fed.mine_spendable_utxo(&*dummy_user, &*bitcoin, Amount::from_sat(1000))
            .await;
        fed.mint_notes_for_user(&*user_send, msats(8)).await;
        assert_eq!(
            user_send.ecash_amounts(),
            vec![msats(1), msats(1), msats(2), msats(4)]
        );

        let (notes, callback) = user_receive.payable_ecash_tx(msats(5)).await;
        callback(user_send.submit_pay_for_ecash(notes).await.unwrap());

        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        // verify transfer occurred and change was made
        assert_eq!(
            user_receive.ecash_amounts(),
            vec![msats(1), msats(2), msats(2)]
        );
        assert_eq!(user_send.ecash_amounts(), vec![msats(1), msats(2)]);

        // verify notes can be broken if we spend ecash
        fed.spend_ecash(&*user_send, msats(1)).await;
        assert_eq!(user_send.ecash_amounts(), vec![msats(2)]);

        fed.spend_ecash(&*user_send, msats(1)).await;
        assert_eq!(user_send.ecash_amounts(), vec![msats(1)]);

        // verify error occurs if we issue too many of one denomination
        user_receive.set_notes_per_denomination(10).await;
        let notes = user_receive.all_stored_ecash().await;
        assert_matches!(user_receive.reissue(notes).await, Err(_));

        // verify we can still issue large amounts (using highest denomination)
        fed.mine_and_mint(&*user_send, &*bitcoin, sats(10_000))
            .await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_tx_submitted() -> Result<()> {
    test(2, |fed, user_send, bitcoin| async move {
        fed.run_consensus_epochs(1).await;

        // to assert we have no pending epochs, we need to make sure
        // height change can't introduce any randomly
        let bitcoin = bitcoin.lock_exclusive().await;
        let user_receive = user_send.new_client_with_peers(peers(&[0]));

        fed.mine_and_mint(&*user_send, &*bitcoin, sats(5000)).await;
        let ecash = fed.spend_ecash(&*user_send, sats(5000)).await;

        assert!(
            !fed.has_pending_epoch().await,
            "Contains pending epochs with {:?}",
            fed.get_pending_epoch_proposals().await
        );
        user_receive.reissue(ecash).await.unwrap();
        fed.run_consensus_epochs(2).await;
        assert!(!fed.has_pending_epoch().await);

        assert_eq!(user_receive.ecash_total(), sats(5000));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_new_block() -> Result<()> {
    test(2, |fed, user, bitcoin| async move {
        // to assert we have no pending epochs, we need to make sure
        // height change didn't couldn't introduce any
        let bitcoin = bitcoin.lock_exclusive().await;

        // make the mint establish at least one block height record
        bitcoin.mine_blocks(1).await;
        fed.run_consensus_epochs(1).await;

        let peg_in_address = user.get_new_peg_in_address().await;
        let (proof, tx) = bitcoin
            .send_and_mine_block(&peg_in_address, Amount::from_sat(1000))
            .await;
        fed.run_consensus_epochs(1).await;

        assert!(
            !fed.has_pending_epoch().await,
            "Contains pending epochs with {:?}",
            fed.get_pending_epoch_proposals().await
        );
        bitcoin
            .mine_blocks(fed.wallet.consensus.finality_delay as u64)
            .await;
        fed.run_consensus_epochs(1).await;
        assert!(!fed.has_pending_epoch().await);

        user.submit_peg_in(proof.clone(), tx.clone()).await.unwrap();

        fed.run_consensus_epochs(2).await;

        assert_eq!(user.ecash_total(), sats(1000));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn audit_negative_balance_sheet_panics() {
    test(2, |fed, user, _| async move {
        fed.mint_notes_for_user(&*user, sats(2000)).await;
        fed.run_consensus_epochs(1).await;
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> Result<()> {
    test(2, |fed, user, _| async move {
        // cannot make change for this invoice (results in unbalanced tx)
        let tx = user.create_mint_tx(Default::default(), sats(1000));
        let response = fed.submit_transaction(tx).await;

        assert!(response.is_err());
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_have_federations_with_one_peer() -> Result<()> {
    test(1, |fed, user, bitcoin| async move {
        bitcoin.mine_blocks(110).await;
        fed.run_consensus_epochs(1).await;
        fed.mine_and_mint(&*user, &*bitcoin, sats(1000)).await;
        assert_eq!(user.ecash_total(), sats(1000));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_get_signed_epoch_history() -> Result<()> {
    test(2, |fed, user, bitcoin| async move {
        fed.mine_and_mint(&*user, &*bitcoin, sats(1000)).await;
        fed.mine_and_mint(&*user, &*bitcoin, sats(1000)).await;

        let pubkey = fed.cfg.consensus.epoch_pk_set.public_key();
        let epoch0 = user.fetch_epoch_history(0, pubkey);
        let epoch1 = user.fetch_epoch_history(1, pubkey);

        assert_eq!(epoch0.verify_sig(&pubkey), Ok(()));
        assert_eq!(epoch0.verify_hash(&None), Ok(()));
        assert_eq!(epoch1.verify_hash(&Some(epoch0)), Ok(()));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_single_peer() -> Result<()> {
    test(4, |fed, user, bitcoin| async move {
        let bitcoin = bitcoin.lock_exclusive().await;
        bitcoin.mine_blocks(1).await;
        fed.run_consensus_epochs(1).await;

        // Keep peer 3 out of consensus
        let online_peers = fed.subset_peers(&[0, 1, 2]).await;
        let peer3 = fed.subset_peers(&[3]).await;
        bitcoin.mine_blocks(100).await;
        online_peers.run_consensus_epochs(1).await;
        bitcoin.mine_blocks(100).await;
        online_peers.run_consensus_epochs(1).await;
        let height = user.await_consensus_block_height(0).await.unwrap();

        // Run until peer 3 has rejoined
        join_all(vec![
            Either::Left(async {
                online_peers.run_consensus_epochs_wait(11).await.unwrap();
            }),
            Either::Right(async {
                peer3.rejoin_consensus().await.unwrap();
                peer3.run_consensus_epochs_wait(1).await.unwrap();
            }),
        ])
        .await;

        // Ensure peer 3 rejoined and caught up to consensus
        let client2 = user.new_client_with_peers(peers(&[1, 2, 3]));

        let new_height = client2.await_consensus_block_height(height).await.unwrap();
        assert_eq!(new_height, height);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_threshold_peers() -> Result<()> {
    test(2, |fed, _user, bitcoin| async move {
        // Simulate a rejoin where all nodes stop
        bitcoin.mine_blocks(110).await;
        fed.run_consensus_epochs(1).await;
        fed.rejoin_consensus().await.unwrap();
        fed.run_consensus_epochs_wait(1).await.unwrap();
        bitcoin.mine_blocks(100).await;
        fed.run_consensus_epochs(1).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_split_peers() -> Result<()> {
    test(4, |fed, user, bitcoin| async move {
        // Simulate a rejoin where half the nodes didn't process the outcomes
        fed.subset_peers(&[0, 1]).await.set_process_outcomes(false);
        bitcoin.mine_blocks(100).await;
        fed.run_consensus_epochs(1).await;
        fed.subset_peers(&[0, 1]).await.set_process_outcomes(true);
        let pubkey = fed.cfg.consensus.epoch_pk_set.public_key();
        let epoch = user
            .new_client_with_peers(peers(&[2]))
            .fetch_epoch_history(0, pubkey);

        fed.force_process_outcome(epoch.clone());
        fed.run_consensus_epochs_wait(1).await.unwrap();
        bitcoin.mine_blocks(100).await;
        fed.run_consensus_epochs(1).await;

        // We cannot process a past epoch and reverse the block height
        let height = user.await_consensus_block_height(0).await.unwrap();
        fed.force_process_outcome(epoch);
        fed.run_consensus_epochs_wait(1).await.unwrap();
        user.await_consensus_block_height(height).await.unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_backup_can_recover_metadata() -> Result<()> {
    test(2, |_fed, user_send, _bitcoin| async move {
        #[derive(Serialize, Deserialize)]
        struct OurMetadata {
            name: String,
        }

        let metadata = Metadata::from_json_serialized(OurMetadata {
            name: "our_name".into(),
        });

        user_send
            .back_up_ecash_to_federation(metadata.clone())
            .await
            .unwrap();

        let mut task_group = TaskGroup::new();

        assert_eq!(
            user_send
                .restore_ecash_from_federation(10, &mut task_group)
                .await
                .unwrap()
                .unwrap(),
            metadata
        );
    })
    .await
}

// this test had to be removed to switch to aleph bft and should be ported to
// the new testing framework.
#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_recovered() -> Result<()> {
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_client_config_downloads() -> Result<()> {
    test(2, |fed, user, _| async move {
        let connect = &fed.connect_info.clone();
        let api = WsFederationApi::from_connect_info(&[connect.clone()]);

        // consensus hash should be the same among all peers
        let res = api.consensus_config_hash().await;
        assert!(res.is_ok());

        fed.run_consensus_epochs(1).await;
        let cfg = api.download_client_config(connect).await.unwrap();
        let cfg = cfg.redecode_raw(&user.decoders()).unwrap();
        assert_eq!(cfg, user.config());

        // cannot download more than once with test settings
        let res = api.download_client_config(connect).await;
        assert_matches!(res, Err(_));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_replay_transactions() -> Result<()> {
    test(4, |fed, user, bitcoin| async move {
        fed.mine_and_mint(&*user, &*bitcoin, sats(5000)).await;

        let tx = user.create_mint_tx(user.all_stored_ecash().await, sats(5000));
        let txid = tx.tx_hash();

        // submit the tx successfully
        let response = fed.submit_transaction(tx.clone()).await;
        assert_matches!(response, Ok(()));
        fed.run_empty_epochs(2).await;
        assert!(fed.find_module_item(fed.mint_id).await.is_some());
        fed.clear_spent_mint_nonces().await;

        // verify resubmitting the tx fails at the API level
        let response = fed.submit_transaction(tx.clone()).await;
        assert_matches!(response, Ok(()));
        fed.run_empty_epochs(2).await;
        assert!(fed.find_module_item(fed.mint_id).await.is_none());

        // verify resubmitting the tx fails at the P2P level
        fed.subset_peers(&[0])
            .await
            .override_proposal(vec![ConsensusItem::Transaction(tx)])
            .await;
        fed.run_empty_epochs(2).await;
        assert!(fed.find_module_item(fed.mint_id).await.is_none());

        // verify status transaction is accepted
        assert!(fed
            .transaction_status(txid)
            .await
            .into_iter()
            .all(|s| matches!(s, Some(TransactionStatus::Accepted { .. }))));
    })
    .await
}

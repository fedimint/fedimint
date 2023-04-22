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

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use assert_matches::assert_matches;
use bitcoin::{Amount, KeyPair};
use fedimint_client_legacy::mint::backup::Metadata;
use fedimint_core::api::{GlobalFederationApi, WsFederationApi};
use fedimint_core::config::CommonModuleGenRegistry;
use fedimint_core::outcome::TransactionStatus;
use fedimint_core::task::{RwLock, TaskGroup};
use fedimint_core::{msats, sats, TieredMulti};
use fedimint_ln_client::contracts::{Preimage, PreimageDecryptionShare};
use fedimint_ln_client::LightningConsensusItem;
use fedimint_logging::LOG_TEST;
use fedimint_mint_server::common::{MintConsensusItem, MintOutputSignatureShare};
use fedimint_server::consensus::TransactionSubmissionError::TransactionError;
use fedimint_server::epoch::ConsensusItem;
use fedimint_server::transaction::TransactionError::UnbalancedTransaction;
use fedimint_wallet_server::common::WalletConsensusItem::PegOutSignature;
use fedimint_wallet_server::common::{PegOutFees, PegOutSignatureItem, Rbf};
use fixtures::{rng, secp, sha256};
use futures::future::{join_all, Either};
use serde::{Deserialize, Serialize};
use threshold_crypto::{SecretKey, SecretKeyShare};
use tracing::log::warn;
use tracing::{debug, info, instrument};

use crate::fixtures::{
    create_lightning_adapter, lightning_test, non_lightning_test, peers, unwrap_item,
    FederationTest,
};

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_in_and_peg_out_with_fees() -> Result<()> {
    non_lightning_test(2, |fed, user, bitcoin| async move {
        // TODO: this should not be needed, but I get errors on `peg_in` below sometimes
        let bitcoin = bitcoin.lock_exclusive().await;
        let peg_in_amount: u64 = 5000;
        let peg_out_amount: u64 = 1200; // amount requires minted change

        let peg_in_address = user.get_new_peg_in_address().await;
        let (proof, tx) = bitcoin
            .send_and_mine_block(&peg_in_address, Amount::from_sat(peg_in_amount))
            .await;
        bitcoin
            .mine_blocks(fed.wallet.consensus.finality_delay as u64)
            .await;
        fed.run_consensus_epochs(1).await;

        user.submit_peg_in(proof, tx).await.unwrap();
        fed.run_consensus_epochs(2).await; // peg in epoch + partial sigs epoch
        assert_eq!(user.ecash_total(), sats(peg_in_amount));

        let peg_out_address = bitcoin.get_new_address().await;
        let (fees, out_point) = user.peg_out(peg_out_amount, &peg_out_address);
        fed.run_consensus_epochs(2).await; // peg-out tx + peg out signing epoch

        assert_matches!(
            unwrap_item(&fed.find_module_item(fed.wallet_id).await),
            PegOutSignature(_)
        );

        let outcome_txid = user.await_peg_out_txid(out_point).await.unwrap();

        assert!(matches!(
            unwrap_item(&fed.find_module_item(fed.wallet_id).await),
            PegOutSignature(PegOutSignatureItem {
                txid,
                ..
            }) if *txid == outcome_txid));

        // confirm we can broadcast at different times
        fed.subset_peers(&[0]).await.broadcast_transactions().await;
        bitcoin.mine_blocks(1).await;
        fed.subset_peers(&[1]).await.broadcast_transactions().await;

        assert_eq!(
            bitcoin.mine_block_and_get_received(&peg_out_address).await,
            sats(peg_out_amount)
        );
        assert_eq!(
            user.ecash_total(),
            sats(peg_in_amount - peg_out_amount) - fees.amount().into()
        );

        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_outs_are_rejected_if_fees_are_too_low() -> Result<()> {
    non_lightning_test(2, |fed, user, bitcoin| async move {
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
#[instrument(name = "peg_outs_are_only_allowed_once_per_epoch")]
async fn wallet_peg_outs_are_only_allowed_once_per_epoch() -> Result<()> {
    non_lightning_test(2, |fed, user, bitcoin| async move {
        let address1 = bitcoin.get_new_address().await;
        let address2 = bitcoin.get_new_address().await;

        fed.mine_and_mint(&*user, &*bitcoin, sats(5000)).await;
        let (fees, _) = user.peg_out(1000, &address1);
        let fees = fees.amount().into();
        user.peg_out(1000, &address2);
        info!(target: LOG_TEST, ?fees, "Tx fee");

        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;

        let received1 = bitcoin.mine_block_and_get_received(&address1).await;
        let received2 = bitcoin.mine_block_and_get_received(&address2).await;

        assert_eq!(received1 + received2, sats(1000));
        // either first peg-out failed OR second failed leaving us unissued change
        assert!(received1 == sats(0) || received2 == sats(0));

        assert_eq!(user.ecash_total(), sats(5000 - 2 * 1000) - fees - fees);
        user.reissue_ecash_failed_tx().await.unwrap();
        fed.run_consensus_epochs(2).await; // reissue the notes from the tx that failed

        assert_eq!(user.ecash_total(), sats(5000 - 1000) - fees);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_peg_outs_support_rbf() -> Result<()> {
    non_lightning_test(2, |fed, user, bitcoin| async move {
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
    non_lightning_test(2, |_fed, user, bitcoin| async move {
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
    non_lightning_test(2, |fed, user, bitcoin| async move {
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
    non_lightning_test(4, |fed, user_send, bitcoin| async move {
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

#[tokio::test(flavor = "multi_thread")]
async fn ecash_cannot_double_spent_with_different_nodes() -> Result<()> {
    non_lightning_test(2, |fed, user1, bitcoin| async move {
        fed.mine_and_mint(&*user1, &*bitcoin, sats(5000)).await;
        let ecash = fed.spend_ecash(&*user1, sats(2000)).await;

        let user2 = user1.new_client_with_peers(peers(&[0]));
        let user3 = user1.new_client_with_peers(peers(&[1]));

        let out2 = user2.reissue(ecash.clone()).await.unwrap();
        let out3 = user3.reissue(ecash).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        let res2 = user2.await_ecash_issued(out2).await;
        let res3 = user3.await_ecash_issued(out3).await;
        assert!(res2.is_err() || res3.is_err()); //no double spend
        assert_eq!(user2.ecash_total() + user3.ecash_total(), sats(2000));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_in_wallet_can_sent_through_a_tx() -> Result<()> {
    non_lightning_test(2, |fed, user_send, bitcoin| async move {
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

async fn drop_peer_3_during_epoch(fed: &FederationTest) -> Result<()> {
    // ensure that peers 1,2,3 create an epoch, so they can see peer 3's bad
    // proposal
    fed.subset_peers(&[1, 2, 3])
        .await
        .run_consensus_epochs(1)
        .await;
    fed.subset_peers(&[0]).await.run_consensus_epochs(1).await;

    // let peers run consensus, but delay peer 0 so if peer 3 wasn't dropped peer 0
    // won't be included
    for maybe_cancelled in join_all(vec![
        Either::Left(fed.subset_peers(&[1, 2]).await.run_consensus_epochs_wait(1)),
        Either::Right(
            fed.subset_peers(&[0, 3])
                .await
                .race_consensus_epoch(vec![Duration::from_millis(500), Duration::from_millis(0)]),
        ),
    ])
    .await
    {
        maybe_cancelled?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_peg_out_psbts() -> Result<()> {
    non_lightning_test(4, |fed, user, bitcoin| async move {
        // This test has many assumptions about bitcoin L1 blocks
        // and FM epochs, so we just lock the node
        let bitcoin = bitcoin.lock_exclusive().await;

        fed.mine_and_mint(&*user, &*bitcoin, sats(3000)).await;

        let peg_out_address = bitcoin.get_new_address().await;
        user.peg_out(1000, &peg_out_address);
        // Ensure peer 0 who received the peg out request is in the next epoch
        fed.subset_peers(&[0, 1, 2])
            .await
            .run_consensus_epochs(1)
            .await;
        fed.subset_peers(&[3]).await.run_consensus_epochs(1).await;

        fed.subset_peers(&[3]).await.override_proposal(vec![]).await;
        drop_peer_3_during_epoch(&fed).await.unwrap();

        fed.broadcast_transactions().await;
        assert_eq!(
            bitcoin.mine_block_and_get_received(&peg_out_address).await,
            sats(1000)
        );
        assert!(fed.subset_peers(&[0, 1, 2]).await.has_dropped_peer(3).await);
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_decryption_shares() -> Result<()> {
    lightning_test(4, |fed, user, bitcoin, gateway, _| async move {
        let bitcoin = bitcoin.lock_exclusive().await;

        let payment_amount = sats(2000);
        fed.mine_and_mint(&*gateway.user, &*bitcoin, sats(3000))
            .await;

        let (txid, invoice, payment_keypair) = user
            .submit_unconfirmed_invoice(payment_amount, "".into())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await;

        let invoice = user
            .await_invoice_confirmation(txid, invoice, payment_keypair)
            .await
            .unwrap();

        // Gateway buys offer, triggering preimage decryption
        let (_, contract_id) = gateway
            .actor
            .buy_preimage_offer(invoice.invoice.payment_hash(), &payment_amount, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // pay for offer

        // propose bad decryption share
        let share = SecretKeyShare::default()
            .decrypt_share_no_verify(&SecretKey::random().public_key().encrypt(""));
        fed.subset_peers(&[3])
            .await
            .override_proposal(vec![ConsensusItem::Module(
                fedimint_core::core::DynModuleConsensusItem::from_typed(
                    fed.ln_id,
                    LightningConsensusItem {
                        contract_id,
                        share: PreimageDecryptionShare(share),
                    },
                ),
            )])
            .await;
        drop_peer_3_during_epoch(&fed).await.unwrap(); // preimage decryption

        user.claim_incoming_contract(contract_id).await.unwrap();
        fed.subset_peers(&[0, 1, 2])
            .await
            .run_consensus_epochs(2)
            .await; // contract to mint notes, sign notes

        assert_eq!(user.ecash_total(), payment_amount);
        assert!(fed.subset_peers(&[0, 1, 2]).await.has_dropped_peer(3).await);
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_blind_sigs() -> Result<()> {
    non_lightning_test(4, |fed, user, bitcoin| async move {
        fed.mine_spendable_utxo(&*user, &*bitcoin, Amount::from_sat(2000))
            .await;
        fed.database_add_notes_for_user(&*user, sats(2000)).await;

        fed.subset_peers(&[3]).await.override_proposal(vec![]).await;
        drop_peer_3_during_epoch(&fed).await.unwrap();

        assert_eq!(user.ecash_total(), sats(2000));
        assert!(fed.subset_peers(&[0, 1, 2]).await.has_dropped_peer(3).await);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_contribute_bad_sigs() -> Result<()> {
    non_lightning_test(4, |fed, user, bitcoin| async move {
        fed.mine_spendable_utxo(&*user, &*bitcoin, Amount::from_sat(2000))
            .await;
        let out_point = fed.database_add_notes_for_user(&*user, sats(2000)).await;
        let bad_proposal = vec![ConsensusItem::Module(
            fedimint_core::core::DynModuleConsensusItem::from_typed(
                fed.mint_id,
                MintConsensusItem {
                    out_point,
                    signatures: MintOutputSignatureShare(TieredMulti::default()),
                },
            ),
        )];

        fed.subset_peers(&[3])
            .await
            .override_proposal(bad_proposal)
            .await;
        drop_peer_3_during_epoch(&fed).await.unwrap();

        assert_eq!(user.ecash_total(), sats(2000));
        assert!(fed.subset_peers(&[0, 1, 2]).await.has_dropped_peer(3).await);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_internal_invoice() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, lightning| async move {
        // Fund the gateway so it can route internal payments
        fed.mine_and_mint(&*gateway.user, &*bitcoin, sats(2000))
            .await;
        fed.mine_and_mint(&*user, &*bitcoin, sats(2000)).await;

        let receiving_user = user.new_client_with_peers(peers(&[0]));

        let confirmed_invoice = {
            let (txid, invoice, payment_keypair) = receiving_user
                .submit_unconfirmed_invoice(sats(1000), "".into())
                .await
                .unwrap();
            fed.run_consensus_epochs(1).await;

            receiving_user
                .await_invoice_confirmation(txid, invoice, payment_keypair)
                .await
                .unwrap()
        };

        let incoming_contract_id = confirmed_invoice.contract_id();
        let invoice = confirmed_invoice.invoice;
        debug!("Receiving User generated invoice: {:?}", invoice);

        let (contract_id, funding_outpoint) =
            user.fund_outgoing_ln_contract(invoice).await.unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        let contract_account = user.get_contract_account(contract_id).await.unwrap();
        assert_eq!(contract_account.amount, sats(1010));
        // 1% LN fee
        debug!(
            "Sending User created outgoing contract: {:?}",
            contract_account
        );

        user.await_outgoing_contract_acceptance(funding_outpoint)
            .await
            .unwrap();
        debug!("Outgoing contract accepted");

        let claim_outpoint = {
            let buy_preimage = gateway
                .actor
                .pay_invoice_buy_preimage(contract_id)
                .await
                .unwrap();

            // buy preimage from offer, decrypt
            fed.run_consensus_epochs(2).await;

            gateway
                .actor
                .pay_invoice_buy_preimage_finalize_and_claim(contract_id, buy_preimage)
                .await
                .unwrap()
        };

        //  claim, mint the notes
        fed.run_consensus_epochs(2).await;

        debug!("Gateway paid invoice on behalf of Sending User");

        gateway
            .actor
            .await_outgoing_contract_claimed(contract_id, claim_outpoint)
            .await
            .unwrap();
        debug!("Gateway claimed outgoing contract");

        let receiving_outpoint = receiving_user
            .claim_incoming_contract(incoming_contract_id)
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // claim incoming contract and mint the notes

        receiving_user
            .await_ecash_issued(receiving_outpoint)
            .await
            .unwrap();
        debug!("User fetched funds paid to incoming contract");

        assert_eq!(user.ecash_total(), sats(2000 - 1010));
        assert_eq!(gateway.user.ecash_total(), sats(2010));
        assert_eq!(receiving_user.ecash_total(), sats(1000));

        if !lightning.is_shared() {
            assert_eq!(lightning.amount_sent().await, sats(0)); // We did not
                                                                // route any payments
                                                                // over the lightning
                                                                // network
        }
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_outgoing_invoice() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, lightning| async move {
        // TODO: in theory this test should work without this lock
        // but for some reason it's flaky
        let bitcoin = bitcoin.lock_exclusive().await;

        let invoice = lightning.invoice(sats(1000), None).await.unwrap();

        fed.mine_and_mint(&*user, &*bitcoin, sats(2000)).await;

        let (contract_id, outpoint) = user.fund_outgoing_ln_contract(invoice).await.unwrap();

        fed.run_consensus_epochs(1).await;

        let contract_account = user.get_contract_account(contract_id).await.unwrap();

        assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee

        user.await_outgoing_contract_acceptance(outpoint)
            .await
            .unwrap();

        let claim_outpoint = gateway.actor.pay_invoice(contract_id).await.unwrap();
        fed.run_consensus_epochs(2).await; // contract to mint notes, sign notes

        gateway
            .actor
            .await_outgoing_contract_claimed(contract_id, claim_outpoint)
            .await
            .unwrap();
        assert_eq!(user.ecash_total(), sats(2000 - 1010));
        assert_eq!(gateway.user.ecash_total(), sats(1010));

        tokio::time::sleep(Duration::from_millis(500)).await; // FIXME need to wait for listfunds to update
        if !lightning.is_shared() {
            assert_eq!(lightning.amount_sent().await, sats(1000));
        }
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_claims_refund_for_internal_invoice() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, lightning| async move {
        // Fund the gateway so it can route internal payments
        fed.mine_and_mint(&*gateway.user, &*bitcoin, sats(2000))
            .await;
        fed.mine_and_mint(&*user, &*bitcoin, sats(2000)).await;

        let receiving_client = user.new_client_with_peers(peers(&[0]));

        let (txid, invoice, payment_keypair) = receiving_client
            .submit_unconfirmed_invoice(sats(1000), "".into())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await;

        let confirmed_invoice = receiving_client
            .await_invoice_confirmation(txid, invoice, payment_keypair)
            .await
            .unwrap();

        let invoice = confirmed_invoice.invoice;
        debug!("Receiving User generated invoice: {:?}", invoice);

        let (contract_id, funding_outpoint) =
            user.fund_outgoing_ln_contract(invoice).await.unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        let contract_account = user.get_contract_account(contract_id).await.unwrap();
        assert_eq!(contract_account.amount, sats(1010));
        // 1% LN fee
        debug!(
            "Sending User created outgoing contract: {:?}",
            contract_account
        );

        user.await_outgoing_contract_acceptance(funding_outpoint)
            .await
            .unwrap();
        debug!("Outgoing contract accepted");

        let response = {
            let buy_preimage = gateway
                .actor
                .pay_invoice_buy_preimage(contract_id)
                .await
                .unwrap();

            // buy preimage from offer, decrypt
            fed.run_consensus_epochs(1).await;

            gateway
                .actor
                .pay_invoice_buy_preimage_finalize_and_claim(contract_id, buy_preimage)
                .await
        };

        assert!(response.is_err());

        // TODO: Assert that the gateway has reclaimed the funds used to buy the
        // preimage

        if !lightning.is_shared() {
            assert_eq!(lightning.amount_sent().await, sats(0)); // We did not
                                                                // route any payments
                                                                // over the lightning
                                                                // network
        }
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn set_lightning_invoice_expiry() -> Result<()> {
    lightning_test(2, |_, _, _, _, lightning| async move {
        let invoice = lightning.invoice(sats(1000), 600.into()).await.unwrap();
        assert_eq!(invoice.expiry_time(), Duration::from_secs(600));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_valid_preimage() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, _| async move {
        let starting_balance = sats(2000);
        let preimage_price = sats(100);

        fed.mine_and_mint(&*gateway.user, &*bitcoin, starting_balance)
            .await;
        assert_eq!(user.ecash_total(), sats(0));
        assert_eq!(gateway.user.ecash_total(), starting_balance);

        // Create lightning invoice whose associated "offer" is accepted by federation
        // consensus
        let (txid, invoice, payment_keypair) = user
            .submit_unconfirmed_invoice(preimage_price, "".into())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await;

        let invoice = user
            .await_invoice_confirmation(txid, invoice, payment_keypair)
            .await
            .unwrap();

        // Gateway deposits ecash to trigger preimage decryption by the federation

        // Usually, the invoice amount needed to buy preimage is equivalent to the
        // `preimage_price` however, for this test, the gateway deposits more
        // than is necessary to check that we never overspend when buying the
        // preimage!
        let invoice_amount = preimage_price + sats(50);
        let (outpoint, contract_id) = gateway
            .actor
            .buy_preimage_offer(invoice.invoice.payment_hash(), &invoice_amount, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

        // Gateway funds have been escrowed

        assert_eq!(
            gateway.user.ecash_total(),
            starting_balance - preimage_price
        );
        assert_eq!(user.ecash_total(), sats(0));

        // Gateway receives decrypted preimage
        let preimage = gateway
            .actor
            .await_preimage_decryption(outpoint)
            .await
            .unwrap();

        // Check that the preimage matches user pubkey & lightning invoice preimage
        let pubkey = invoice.keypair.x_only_public_key().0;
        assert_eq!(pubkey, preimage.to_public_key().unwrap());
        assert_eq!(&sha256(&pubkey.serialize()), invoice.invoice.payment_hash());

        // User claims their ecash
        user.claim_incoming_contract(contract_id).await.unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

        // Ecash notes have been transferred from gateway to user

        assert_eq!(
            gateway.user.ecash_total(),
            starting_balance - preimage_price
        );
        assert_eq!(user.ecash_total(), preimage_price);
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_invalid_preimage() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, _| async move {
        let starting_balance = sats(2000);
        let payment_amount = sats(100);

        fed.mine_and_mint(&*gateway.user, &*bitcoin, starting_balance)
            .await;
        assert_eq!(user.ecash_total(), sats(0));
        assert_eq!(gateway.user.ecash_total(), starting_balance);

        // Manually construct offer where sha256(preimage) != hash
        let kp = KeyPair::new(&secp(), &mut rng());
        let payment_hash = sha256(&[0]);
        let offer_tx = user.create_offer_tx(
            payment_amount,
            payment_hash,
            Preimage(kp.x_only_public_key().0.serialize()),
            None,
        );
        fed.submit_transaction(offer_tx).await.unwrap();
        fed.run_consensus_epochs(1).await; // process offer

        // Gateway escrows ecash to trigger preimage decryption by the federation
        let (_, contract_id) = gateway
            .actor
            .buy_preimage_offer(&payment_hash, &payment_amount, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

        // Gateway funds have been escrowed
        assert_eq!(
            gateway.user.ecash_total(),
            starting_balance - payment_amount
        );
        assert_eq!(user.ecash_total(), sats(0));

        // User gets error when they try to claim gateway's escrowed ecash
        let response = user.claim_incoming_contract(contract_id).await;
        assert!(response.is_err());

        // Gateway is refunded
        gateway
            .client
            .refund_incoming_contract(contract_id)
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

        // Gateway has clawed back their escrowed funds
        assert_eq!(gateway.user.ecash_total(), starting_balance);
        assert_eq!(user.ecash_total(), sats(0));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_cannot_claim_invalid_preimage() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, lightning| async move {
        let invoice = lightning.invoice(sats(1000), None).await.unwrap();

        fed.mine_and_mint(&*user, &*bitcoin, sats(1010)).await; // 1% LN fee
        let (contract_id, _) = user.fund_outgoing_ln_contract(invoice).await.unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        // Create a random preimage that has no association to the contract invoice
        let rand_slice: [u8; 32] = rand::random();
        let bad_preimage = Preimage(rand_slice);
        let response = gateway
            .client
            .claim_outgoing_contract(contract_id, bad_preimage)
            .await;
        assert!(response.is_err());

        fed.run_empty_epochs(1).await; // if valid would create contract to mint notes
        assert_eq!(fed.find_module_item(fed.ln_id).await, None);
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_can_abort_payment_to_return_user_funds() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, gateway, lightning| async move {
        let invoice = lightning.invoice(sats(1000), None).await.unwrap();

        fed.mine_and_mint(&*user, &*bitcoin, sats(1010)).await; // 1% LN fee
        let (contract_id, _) = user.fund_outgoing_ln_contract(invoice).await.unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        let contract = gateway
            .client
            .get_outgoing_contract(contract_id)
            .await
            .unwrap();
        gateway.client.save_outgoing_payment(contract).await;

        // Gateway fails to acquire preimage, so it cancels the contract so the user can
        // try another one
        gateway
            .client
            .abort_outgoing_payment(contract_id)
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await;
        let outpoint = user.try_refund_outgoing_contract(contract_id).await;
        fed.run_consensus_epochs(2).await;
        user.await_ecash_issued(outpoint.unwrap()).await.unwrap();
        assert_eq!(user.ecash_total(), sats(1010));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_tx_submitted() -> Result<()> {
    non_lightning_test(2, |fed, user_send, bitcoin| async move {
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
    non_lightning_test(2, |fed, user, bitcoin| async move {
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
    non_lightning_test(2, |fed, user, _| async move {
        fed.mint_notes_for_user(&*user, sats(2000)).await;
        fed.run_consensus_epochs(1).await;
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> Result<()> {
    non_lightning_test(2, |fed, user, _| async move {
        // cannot make change for this invoice (results in unbalanced tx)
        let tx = user.create_mint_tx(Default::default(), sats(1000));
        let response = fed.submit_transaction(tx).await;

        assert_matches!(
            response,
            Err(TransactionError(UnbalancedTransaction { .. }))
        );
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_have_federations_with_one_peer() -> Result<()> {
    non_lightning_test(1, |fed, user, bitcoin| async move {
        bitcoin.mine_blocks(110).await;
        fed.run_consensus_epochs(1).await;
        fed.mine_and_mint(&*user, &*bitcoin, sats(1000)).await;
        assert_eq!(user.ecash_total(), sats(1000));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_get_signed_epoch_history() -> Result<()> {
    non_lightning_test(2, |fed, user, bitcoin| async move {
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
    non_lightning_test(4, |fed, user, bitcoin| async move {
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
    non_lightning_test(2, |fed, _user, bitcoin| async move {
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
async fn ecash_backup_can_recover_metadata() -> Result<()> {
    non_lightning_test(2, |_fed, user_send, _bitcoin| async move {
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

#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_recovered() -> Result<()> {
    non_lightning_test(2, |fed, user_send, bitcoin| async move {
        let user_receive = user_send.new_client_with_peers(peers(&[0, 1, 2]));

        fed.mine_and_mint(&*user_send, &*bitcoin, sats(5000)).await;
        assert_eq!(user_send.ecash_total(), sats(5000));
        assert_eq!(user_receive.ecash_total(), sats(0));

        user_send
            .back_up_ecash_to_federation(Metadata::empty())
            .await
            .unwrap();

        user_send.remove_all_stored_ecash().await.unwrap();

        assert_eq!(user_send.ecash_total(), sats(0));

        let mut task_group = TaskGroup::new();

        user_send.restore_ecash(10, &mut task_group);
        assert_eq!(user_send.ecash_total(), sats(5000));

        let ecash = fed.spend_ecash(&*user_send, sats(3500)).await;
        user_receive.reissue(ecash).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        user_send.restore_ecash(10, &mut task_group);
        assert_eq!(user_send.ecash_total(), sats(1500));

        // Generate a lot of epochs, to test multi-threaded fetching
        // and possibly other things that come with more epochs to
        // process.
        for _ in 0..10 {
            let ecash = fed.spend_ecash(&*user_send, sats(10)).await;
            user_receive.reissue(ecash).await.unwrap();
            fed.run_consensus_epochs(2).await; // process transaction + sign new
                                               // notes
        }

        user_send.restore_ecash(10, &mut task_group);
        assert_eq!(user_send.ecash_total(), sats(1400));

        task_group.join_all(None).await.unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_client_config_downloads() -> Result<()> {
    non_lightning_test(2, |fed, user, _| async move {
        let connect = &fed.connect_info.clone();
        let api = WsFederationApi::from_connect_info(&[connect.clone()]);
        let reg = CommonModuleGenRegistry::default();

        // consensus hash should be the same amoung all peers
        let res = api.consensus_config_hash().await;
        assert!(res.is_ok());

        // fed needs to run an epoch to combine shares and verify sig
        let res = api.download_client_config(connect, reg.clone()).await;
        assert_matches!(res, Err(_));

        fed.run_consensus_epochs(1).await;
        let cfg = api
            .download_client_config(connect, reg.clone())
            .await
            .unwrap();
        assert_eq!(cfg, user.config());

        // cannot download more than once with test settings
        let res = api.download_client_config(connect, reg.clone()).await;
        assert_matches!(res, Err(_));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_replay_transactions() -> Result<()> {
    non_lightning_test(4, |fed, user, bitcoin| async move {
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

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_can_reconnect() -> Result<()> {
    lightning_test(2, |fed, user, bitcoin, mut gateway, lightning| async move {
        // TODO: in theory this test should work without this lock
        // but for some reason it's flaky
        let bitcoin = bitcoin.lock_exclusive().await;

        let invoice = lightning.invoice(sats(1000), None).await.unwrap();

        fed.mine_and_mint(&*user, &*bitcoin, sats(2000)).await;

        let (contract_id, outpoint) = user.fund_outgoing_ln_contract(invoice).await.unwrap();

        fed.run_consensus_epochs(1).await;

        let contract_account = user.get_contract_account(contract_id).await.unwrap();
        assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee

        user.await_outgoing_contract_acceptance(outpoint)
            .await
            .unwrap();

        // Replace the gateway's lightning connection and verify that payments still
        // succeed
        let new_lnrpc = create_lightning_adapter(gateway.node, TaskGroup::new()).await;
        gateway.adapter = Arc::new(RwLock::new(new_lnrpc));

        let claim_outpoint = gateway.actor.pay_invoice(contract_id).await.unwrap();
        fed.run_consensus_epochs(2).await; // contract to mint notes, sign notes

        gateway
            .actor
            .await_outgoing_contract_claimed(contract_id, claim_outpoint)
            .await
            .unwrap();
        assert_eq!(user.ecash_total(), sats(2000 - 1010));
        assert_eq!(gateway.user.ecash_total(), sats(1010));

        tokio::time::sleep(Duration::from_millis(500)).await; // FIXME need to wait for listfunds to update
        if !lightning.is_shared() {
            assert_eq!(lightning.amount_sent().await, sats(1000));
        }
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

mod fixtures;

use std::time::Duration;

use anyhow::Result;
use assert_matches::assert_matches;
use bitcoin::{Amount, KeyPair};
use fedimint_api::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_api::task::TaskGroup;
use fedimint_api::{msats, sats, TieredMulti};
use fedimint_ln::contracts::{Preimage, PreimageDecryptionShare};
use fedimint_ln::LightningConsensusItem;
use fedimint_mint::{MintConsensusItem, MintOutputSignatureShare};
use fedimint_server::consensus::TransactionSubmissionError::TransactionError;
use fedimint_server::epoch::ConsensusItem;
use fedimint_server::transaction::legacy::Output;
use fedimint_server::transaction::TransactionError::UnbalancedTransaction;
use fedimint_wallet::PegOutSignatureItem;
use fedimint_wallet::WalletConsensusItem::PegOutSignature;
use fixtures::{rng, secp, sha256};
use futures::future::{join_all, Either};
use mint_client::transaction::TransactionBuilder;
use mint_client::{ClientError, ConfigVerifyError};
use threshold_crypto::{SecretKey, SecretKeyShare};
use tracing::debug;

use crate::fixtures::{assert_ci, peers, test, FederationTest};

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_and_peg_out_with_fees() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        let peg_in_amount: u64 = 5000;
        let peg_out_amount: u64 = 1200; // amount requires minted change

        let peg_in_address = user.client.get_new_pegin_address(rng()).await;
        let (proof, tx) =
            bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(peg_in_amount));
        bitcoin.mine_blocks(fed.wallet.consensus.finality_delay as u64);
        fed.run_consensus_epochs(1).await;

        user.client.peg_in(proof, tx, rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // peg in epoch + partial sigs epoch
        user.assert_total_notes(sats(peg_in_amount)).await;

        let peg_out_address = bitcoin.get_new_address();
        let (fees, out_point) = user.peg_out(peg_out_amount, &peg_out_address).await;
        fed.run_consensus_epochs(2).await; // peg-out tx + peg out signing epoch

        assert_matches!(
            assert_ci(
                fed.last_consensus_items()
                    .iter()
                    .find(|ci| {
                        let ConsensusItem::Module(mci) = ci else { return false };
                        mci.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_WALLET
                    })
                    .unwrap()
            ),
            PegOutSignature(_)
        );

        let outcome_txid = user
            .client
            .wallet_client()
            .await_peg_out_outcome(out_point)
            .await
            .unwrap();
        assert!(matches!(
            assert_ci(
                fed.last_consensus_items()
                    .iter()
                    .find(|ci| {
                        let ConsensusItem::Module(mci) = ci else { return false };
                        mci.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_WALLET
                    })
                    .unwrap()

            ),
            PegOutSignature(PegOutSignatureItem {
                txid,
                ..
            }) if *txid == outcome_txid));

        fed.broadcast_transactions().await;
        assert_eq!(
            bitcoin.mine_block_and_get_received(&peg_out_address),
            sats(peg_out_amount)
        );
        user.assert_total_notes(sats(peg_in_amount - peg_out_amount) - fees)
            .await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_are_rejected_if_fees_are_too_low() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        let peg_out_amount = Amount::from_sat(1000);
        let peg_out_address = bitcoin.get_new_address();

        fed.mine_and_mint(&user, &*bitcoin, sats(3000)).await;
        let mut peg_out = user
            .client
            .new_peg_out_with_fees(peg_out_amount, peg_out_address.clone())
            .await
            .unwrap();

        // Lower rate below FeeConsensus
        peg_out.fees.fee_rate.sats_per_kvb = 10;
        // TODO: return a better error message to clients
        assert!(user.client.peg_out(peg_out, rng()).await.is_err());
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_are_only_allowed_once_per_epoch() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        let address1 = bitcoin.get_new_address();
        let address2 = bitcoin.get_new_address();

        fed.mine_and_mint(&user, &*bitcoin, sats(5000)).await;
        let (fees, _) = user.peg_out(1000, &address1).await;
        user.peg_out(1000, &address2).await;

        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;

        let received1 = bitcoin.mine_block_and_get_received(&address1);
        let received2 = bitcoin.mine_block_and_get_received(&address2);

        assert_eq!(received1 + received2, sats(1000));
        user.client.reissue_pending_notes(rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // reissue the notes from the tx that failed
        user.assert_total_notes(sats(5000 - 1000) - fees).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_ins_that_are_unconfirmed_are_rejected() -> Result<()> {
    test(2, |_fed, user, bitcoin, _, _| async move {
        let peg_in_address = user.client.get_new_pegin_address(rng()).await;
        let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(10000));
        let result = user.client.peg_in(proof, tx, rng()).await;

        // TODO make return error more useful
        assert!(result.is_err());
        // confirm that the issuance was saved, even if the tx is rejected
        assert!(!user.client.list_active_issuances().await.is_empty());
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_must_wait_for_available_utxos() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        let address1 = bitcoin.get_new_address();
        let address2 = bitcoin.get_new_address();

        fed.mine_and_mint(&user, &*bitcoin, sats(5000)).await;
        user.peg_out(1000, &address1).await;

        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;
        assert_eq!(bitcoin.mine_block_and_get_received(&address1), sats(1000));

        // The change UTXO is still finalizing
        let response = user
            .client
            .new_peg_out_with_fees(Amount::from_sat(2000), address2.clone());
        assert_matches!(response.await, Err(ClientError::PegOutWaitingForUTXOs));

        bitcoin.mine_blocks(100);
        fed.run_consensus_epochs(1).await;
        user.peg_out(2000, &address2).await;
        fed.run_consensus_epochs(2).await;
        fed.broadcast_transactions().await;
        assert_eq!(bitcoin.mine_block_and_get_received(&address2), sats(2000));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_exchanged_directly_between_users() -> Result<()> {
    test(4, |fed, user_send, bitcoin, _, _| async move {
        let user_receive = user_send.new_user_with_peers(peers(&[0, 1, 2])).await;

        fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
        assert_eq!(user_send.total_notes().await, sats(5000));
        assert_eq!(user_receive.total_notes().await, sats(0));

        let ecash = fed.spend_ecash(&user_send, sats(3500)).await;
        user_receive.client.reissue(ecash, rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        user_send.assert_total_notes(sats(1500)).await;
        user_receive.assert_total_notes(sats(3500)).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_cannot_double_spent_with_different_nodes() -> Result<()> {
    test(2, |fed, user1, bitcoin, _, _| async move {
        fed.mine_and_mint(&user1, &*bitcoin, sats(5000)).await;
        let ecash = fed.spend_ecash(&user1, sats(2000)).await;

        let user2 = user1.new_user_with_peers(peers(&[0])).await;
        let user3 = user1.new_user_with_peers(peers(&[1])).await;

        let out2 = user2.client.reissue(ecash.clone(), rng()).await.unwrap();
        let out3 = user3.client.reissue(ecash, rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        let res2 = user2.client.fetch_notes(out2).await;
        let res3 = user3.client.fetch_notes(out3).await;
        assert!(res2.is_err() || res3.is_err()); //no double spend
        assert_eq!(
            user2.total_notes().await + user3.total_notes().await,
            sats(2000)
        );
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_in_wallet_can_sent_through_a_tx() -> Result<()> {
    test(2, |fed, user_send, bitcoin, _, _| async move {
        let dummy_user = user_send.new_user_with_peers(peers(&[0])).await;
        let user_receive = user_send.new_user_with_peers(peers(&[0])).await;
        user_send
            .client
            .mint_client()
            .set_notes_per_denomination(1)
            .await;
        user_receive
            .client
            .mint_client()
            .set_notes_per_denomination(1)
            .await;

        fed.mine_spendable_utxo(&dummy_user, &*bitcoin, Amount::from_sat(1000))
            .await;
        fed.mint_notes_for_user(&user_send, msats(8)).await;
        let notes = vec![msats(1), msats(1), msats(2), msats(4)];
        assert_eq!(user_send.note_amounts().await, notes);

        user_receive
            .client
            .receive_notes(msats(5), |notes| async {
                user_send
                    .client
                    .pay_to_blind_nonces(notes, rng())
                    .await
                    .unwrap()
            })
            .await;

        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        user_receive
            .assert_note_amounts(vec![msats(1), msats(2), msats(2)])
            .await;
        user_send
            .assert_note_amounts(vec![msats(1), msats(2)])
            .await;

        // verify error occurs if we issue too many of one denomination
        user_receive
            .client
            .mint_client()
            .set_notes_per_denomination(10)
            .await;
        let notes = user_receive.client.notes().await;
        assert_matches!(user_receive.client.reissue(notes, rng()).await, Err(_));
    })
    .await
}

async fn drop_peer_3_during_epoch(fed: &FederationTest) -> Result<()> {
    // ensure that peers 1,2,3 create an epoch, so they can see peer 3's bad proposal
    fed.subset_peers(&[1, 2, 3]).run_consensus_epochs(1).await;
    fed.subset_peers(&[0]).run_consensus_epochs(1).await;

    // let peers run consensus, but delay peer 0 so if peer 3 wasn't dropped peer 0 won't be included
    for maybe_cancelled in join_all(vec![
        Either::Left(fed.subset_peers(&[1, 2]).await_consensus_epochs(1)),
        Either::Right(
            fed.subset_peers(&[0, 3])
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
    test(4, |fed, user, bitcoin, _, _| async move {
        fed.mine_and_mint(&user, &*bitcoin, sats(3000)).await;

        let peg_out_address = bitcoin.get_new_address();
        user.peg_out(1000, &peg_out_address).await;
        // Ensure peer 0 who received the peg out request is in the next epoch
        fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(1).await;
        fed.subset_peers(&[3])
            .await_consensus_epochs(1)
            .await
            .unwrap();

        fed.subset_peers(&[3]).override_proposal(vec![]);
        drop_peer_3_during_epoch(&fed).await.unwrap();

        fed.broadcast_transactions().await;
        assert_eq!(
            bitcoin.mine_block_and_get_received(&peg_out_address),
            sats(1000)
        );
        assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_decryption_shares() -> Result<()> {
    test(4, |fed, user, bitcoin, gateway, _| async move {
        let payment_amount = sats(2000);
        fed.mine_and_mint(&gateway.user, &*bitcoin, sats(3000))
            .await;

        // Create lightning invoice whose associated "offer" is accepted by federation consensus
        let invoice = tokio::join!(
            user.client
                .generate_invoice(payment_amount, "".into(), rng(), None),
            fed.await_consensus_epochs(1) // create offer
        )
        .0
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
            .override_proposal(vec![ConsensusItem::Module(
                fedimint_api::core::DynModuleConsensusItem::from_typed(
                    LEGACY_HARDCODED_INSTANCE_ID_LN,
                    LightningConsensusItem {
                        contract_id,
                        share: PreimageDecryptionShare(share),
                    },
                ),
            )]);
        drop_peer_3_during_epoch(&fed).await.unwrap(); // preimage decryption

        user.client
            .claim_incoming_contract(contract_id, rng())
            .await
            .unwrap();
        fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(2).await; // contract to mint notes, sign notes

        user.assert_total_notes(payment_amount).await;
        assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_blind_sigs() -> Result<()> {
    test(4, |fed, user, bitcoin, _, _| async move {
        fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000))
            .await;
        fed.database_add_notes_for_user(&user, sats(2000)).await;

        fed.subset_peers(&[3]).override_proposal(vec![]);
        drop_peer_3_during_epoch(&fed).await.unwrap();

        user.assert_total_notes(sats(2000)).await;
        assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_contribute_bad_sigs() -> Result<()> {
    test(4, |fed, user, bitcoin, _, _| async move {
        fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000))
            .await;
        let out_point = fed.database_add_notes_for_user(&user, sats(2000)).await;
        let bad_proposal = vec![ConsensusItem::Module(
            fedimint_api::core::DynModuleConsensusItem::from_typed(
                LEGACY_HARDCODED_INSTANCE_ID_MINT,
                MintConsensusItem {
                    out_point,
                    signatures: MintOutputSignatureShare(TieredMulti::default()),
                },
            ),
        )];

        fed.subset_peers(&[3]).override_proposal(bad_proposal);
        drop_peer_3_during_epoch(&fed).await.unwrap();

        user.assert_total_notes(sats(2000)).await;
        assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_internal_invoice() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, lightning| async move {
        // Fund the gateway so it can route internal payments
        fed.mine_and_mint(&gateway.user, &*bitcoin, sats(2000))
            .await;
        fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;

        let receiving_user = user.new_user_with_peers(peers(&[0])).await;

        let confirmed_invoice = tokio::join!(
            receiving_user
                .client
                .generate_invoice(sats(1000), "".into(), rng(), None),
            fed.await_consensus_epochs(1),
        )
        .0
        .unwrap();
        let incoming_contract_id = confirmed_invoice.contract_id();
        let invoice = confirmed_invoice.invoice;
        debug!("Receiving User generated invoice: {:?}", invoice);

        let (contract_id, funding_outpoint) = user
            .client
            .fund_outgoing_ln_contract(invoice, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        let contract_account = user
            .client
            .ln_client()
            .get_contract_account(contract_id)
            .await
            .unwrap();
        assert_eq!(contract_account.amount, sats(1010));
        // 1% LN fee
        debug!(
            "Sending User created outgoing contract: {:?}",
            contract_account
        );

        user.client
            .await_outgoing_contract_acceptance(funding_outpoint)
            .await
            .unwrap();
        debug!("Outgoing contract accepted");

        let claim_outpoint = tokio::join!(
            gateway
                .actor
                .pay_invoice(gateway.adapter.clone(), contract_id),
            async {
                // buy preimage from offer, decrypt preimage, claim outgoing contract, mint the notes
                fed.await_consensus_epochs(4).await.unwrap();
            }
        )
        .0
        .unwrap();
        debug!("Gateway paid invoice on behalf of Sending User");

        gateway
            .actor
            .await_outgoing_contract_claimed(contract_id, claim_outpoint)
            .await
            .unwrap();
        debug!("Gateway claimed outgoing contract");

        let receiving_outpoint = receiving_user
            .client
            .claim_incoming_contract(incoming_contract_id, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // claim incoming contract and mint the notes

        receiving_user
            .client
            .fetch_notes(receiving_outpoint)
            .await
            .unwrap();
        debug!("User fetched funds paid to incoming contract");

        user.assert_total_notes(sats(2000 - 1010)).await; // user sent a 1000 sat + 10 sat fee invoice
        gateway.user.assert_total_notes(sats(2010)).await; // gateway routed internally and earned fee
        receiving_user.assert_total_notes(sats(1000)).await; // this user received the 1000 sat invoice

        assert_eq!(lightning.amount_sent().await, sats(0)); // We did not route any payments over the lightning network
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_outgoing_invoice() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, lightning| async move {
        let invoice = lightning.invoice(sats(1000), None).await;

        fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;

        let (contract_id, outpoint) = user
            .client
            .fund_outgoing_ln_contract(invoice, rng())
            .await
            .unwrap();

        let ln_client = user.client.ln_client();
        let (contract_account, _) = tokio::join!(
            ln_client.get_contract_account(contract_id),
            fed.run_consensus_epochs(1)
        );
        assert_eq!(contract_account.unwrap().amount, sats(1010)); // 1% LN fee

        user.client
            .await_outgoing_contract_acceptance(outpoint)
            .await
            .unwrap();

        let claim_outpoint = gateway
            .actor
            .pay_invoice(gateway.adapter.clone(), contract_id)
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // contract to mint notes, sign notes

        gateway
            .actor
            .await_outgoing_contract_claimed(contract_id, claim_outpoint)
            .await
            .unwrap();
        user.assert_total_notes(sats(2000 - 1010)).await;
        gateway.user.assert_total_notes(sats(1010)).await;

        tokio::time::sleep(Duration::from_millis(500)).await; // FIXME need to wait for listfunds to update
        assert_eq!(lightning.amount_sent().await, sats(1000));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_claims_refund_for_internal_invoice() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, lightning| async move {
        // Fund the gateway so it can route internal payments
        fed.mine_and_mint(&gateway.user, &*bitcoin, sats(2000))
            .await;
        fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;

        let receiving_client = user.new_user_with_peers(peers(&[0])).await;

        let confirmed_invoice = tokio::join!(
            receiving_client
                .client
                .generate_invoice(sats(1000), "".into(), rng(), None),
            fed.await_consensus_epochs(1),
        )
        .0
        .unwrap();
        let invoice = confirmed_invoice.invoice;
        debug!("Receiving User generated invoice: {:?}", invoice);

        let (contract_id, funding_outpoint) = user
            .client
            .fund_outgoing_ln_contract(invoice, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        let contract_account = user
            .client
            .ln_client()
            .get_contract_account(contract_id)
            .await
            .unwrap();
        assert_eq!(contract_account.amount, sats(1010));
        // 1% LN fee
        debug!(
            "Sending User created outgoing contract: {:?}",
            contract_account
        );

        user.client
            .await_outgoing_contract_acceptance(funding_outpoint)
            .await
            .unwrap();
        debug!("Outgoing contract accepted");

        let response = tokio::join!(
            gateway
                .actor
                .pay_invoice(gateway.adapter.clone(), contract_id),
            async {
                // we should run 4 epocks to buy preimage from offer, decrypt preimage, claim outgoing contract, mint the notes
                // but we only run 1 epoch to simulate timeout in preimage decryption
                // This results in an error and the gateway reclaims funds used to buy preimage
                fed.await_consensus_epochs(1).await.unwrap();
            }
        )
        .0;
        assert!(response.is_err());

        // TODO: Assert that the gateway has reclaimed the funds used to buy the preimage

        assert_eq!(lightning.amount_sent().await, sats(0)); // We did not route any payments over the lightning network
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn set_lightning_invoice_expiry() -> Result<()> {
    test(2, |_, _, _, _, lightning| async move {
        let invoice = lightning.invoice(sats(1000), 600.into());
        assert_eq!(invoice.await.expiry_time(), Duration::from_secs(600));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_valid_preimage() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, _| async move {
        let starting_balance = sats(2000);
        let preimage_price = sats(100);

        fed.mine_and_mint(&gateway.user, &*bitcoin, starting_balance)
            .await;
        assert_eq!(user.total_notes().await, sats(0));
        assert_eq!(gateway.user.total_notes().await, starting_balance);

        // Create lightning invoice whose associated "offer" is accepted by federation consensus
        let invoice = tokio::join!(
            user.client
                .generate_invoice(preimage_price, "".into(), rng(), None),
            fed.await_consensus_epochs(1),
        )
        .0
        .unwrap();

        // Gateway deposits ecash to trigger preimage decryption by the federation

        // Usually, the invoice amount needed to buy preimage is equivalent to the `preimage_price`
        // however, for this test, the gateway deposits more than is necessary to check that
        // we never overspend when buying the preimage!
        let invoice_amount = preimage_price + sats(50);
        let (outpoint, contract_id) = gateway
            .actor
            .buy_preimage_offer(invoice.invoice.payment_hash(), &invoice_amount, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

        // Gateway funds have been escrowed
        gateway
            .user
            .assert_total_notes(starting_balance - preimage_price)
            .await;
        user.assert_total_notes(sats(0)).await;

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
        user.client
            .claim_incoming_contract(contract_id, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

        // Ecash notes have been transferred from gateway to user
        gateway
            .user
            .assert_total_notes(starting_balance - preimage_price)
            .await;
        user.assert_total_notes(preimage_price).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_invalid_preimage() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, _| async move {
        let starting_balance = sats(2000);
        let payment_amount = sats(100);

        fed.mine_and_mint(&gateway.user, &*bitcoin, starting_balance)
            .await;
        assert_eq!(user.total_notes().await, sats(0));
        assert_eq!(gateway.user.total_notes().await, starting_balance);

        // Manually construct offer where sha256(preimage) != hash
        let kp = KeyPair::new(&secp(), &mut rng());
        let payment_hash = sha256(&[0]);
        let offer_output = user.client.ln_client().create_offer_output(
            payment_amount,
            payment_hash,
            Preimage(kp.x_only_public_key().0.serialize()),
            None,
        );
        let mut builder = TransactionBuilder::default();
        builder.output(Output::LN(offer_output));
        user.client
            .submit_tx_with_change(builder, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // process offer

        // Gateway escrows ecash to trigger preimage decryption by the federation
        let (_, contract_id) = gateway
            .actor
            .buy_preimage_offer(&payment_hash, &payment_amount, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

        // Gateway funds have been escrowed
        gateway
            .user
            .assert_total_notes(starting_balance - payment_amount)
            .await;
        user.assert_total_notes(sats(0)).await;

        // User gets error when they try to claim gateway's escrowed ecash
        let response = user
            .client
            .claim_incoming_contract(contract_id, rng())
            .await;
        assert!(response.is_err());

        // Gateway is refunded
        let _outpoint = gateway
            .client
            .refund_incoming_contract(contract_id, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

        // Gateway has clawed back their escrowed funds
        gateway.user.assert_total_notes(starting_balance).await;
        user.assert_total_notes(sats(0)).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_cannot_claim_invalid_preimage() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, lightning| async move {
        let invoice = lightning.invoice(sats(1000), None);

        fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
        let (contract_id, _) = user
            .client
            .fund_outgoing_ln_contract(invoice.await, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        // Create a random preimage that has no association to the contract invoice
        let rand_slice: [u8; 32] = rand::random();
        let bad_preimage = Preimage(rand_slice);
        let response = gateway
            .client
            .claim_outgoing_contract(contract_id, bad_preimage, rng())
            .await;
        assert!(response.is_err());

        bitcoin.mine_blocks(100); // create non-empty epoch
        fed.run_consensus_epochs(1).await; // if valid would create contract to mint notes

        let ln_items = fed
            .last_consensus_items()
            .iter()
            .filter(|item| match item {
                ConsensusItem::Module(mci) => {
                    mci.module_instance_id() == LEGACY_HARDCODED_INSTANCE_ID_LN
                }
                _ => false,
            })
            .count();
        assert_eq!(ln_items, 0);
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_can_abort_payment_to_return_user_funds() -> Result<()> {
    test(2, |fed, user, bitcoin, gateway, lightning| async move {
        let invoice = lightning.invoice(sats(1000), None);

        fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
        let (contract_id, _) = user
            .client
            .fund_outgoing_ln_contract(invoice.await, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await; // send notes to LN contract

        gateway
            .client
            .save_outgoing_payment(
                gateway
                    .client
                    .ln_client()
                    .get_outgoing_contract(contract_id)
                    .await
                    .unwrap(),
            )
            .await;

        // Gateway fails to acquire preimage, so it cancels the contract so the user can try another one
        gateway
            .client
            .abort_outgoing_payment(contract_id)
            .await
            .unwrap();
        fed.run_consensus_epochs(1).await;
        let outpoint = user
            .client
            .try_refund_outgoing_contract(contract_id, rng())
            .await
            .unwrap();
        fed.run_consensus_epochs(2).await;
        user.client.fetch_notes(outpoint).await.unwrap();
        assert_eq!(user.total_notes().await, sats(1010));
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_tx_submitted() -> Result<()> {
    test(2, |fed, user_send, bitcoin, _, _| async move {
        let user_receive = user_send.new_user_with_peers(peers(&[0])).await;

        fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
        let ecash = fed.spend_ecash(&user_send, sats(5000)).await;

        // If epochs run before the reissue tx, then there won't be any notes to fetch
        join_all(vec![
            Either::Left(async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                user_receive.client.reissue(ecash, rng()).await.unwrap();
            }),
            Either::Right(async {
                fed.await_consensus_epochs(2).await.unwrap();
            }),
        ])
        .await;

        user_receive.assert_total_notes(sats(5000)).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_new_block() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        let peg_in_address = user.client.get_new_pegin_address(rng()).await;
        bitcoin.mine_blocks(100);
        let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(1000));
        fed.run_consensus_epochs(1).await;

        // If epochs run before the blocks are mined, user won't be able to peg-in
        join_all(vec![
            Either::Left(async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                bitcoin.mine_blocks(fed.wallet.consensus.finality_delay as u64);
            }),
            Either::Right(async { fed.await_consensus_epochs(1).await.unwrap() }),
        ])
        .await;

        user.client.peg_in(proof, tx, rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // peg-in + blind sign
        user.assert_total_notes(sats(1000)).await;
        assert_eq!(fed.max_balance_sheet(), 0);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn audit_negative_balance_sheet_panics() {
    test(2, |fed, user, _, _, _| async move {
        fed.mint_notes_for_user(&user, sats(2000)).await;
        fed.run_consensus_epochs(1).await;
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> Result<()> {
    test(2, |fed, user, _, _, _| async move {
        // cannot make change for this invoice (results in unbalanced tx)
        let builder = TransactionBuilder::default();
        let mint = user.client.mint_client();

        let mut dbtx = mint.start_dbtx().await;
        let tx = builder
            .build_with_change(
                user.client.mint_client(),
                &mut dbtx,
                rng(),
                vec![sats(1000)],
                &secp(),
            )
            .await;
        let response = fed.submit_transaction(tx.into_type_erased()).await;

        assert_matches!(
            response,
            Err(TransactionError(UnbalancedTransaction { .. }))
        );
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_have_federations_with_one_peer() -> Result<()> {
    test(1, |fed, user, bitcoin, _, _| async move {
        bitcoin.mine_blocks(110);
        fed.run_consensus_epochs(1).await;
        fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;
        user.assert_total_notes(sats(1000)).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_get_signed_epoch_history() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;
        fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;

        let pubkey = fed.cfg.consensus.epoch_pk_set.public_key();
        let epoch0 = user.client.fetch_epoch_history(0, pubkey).await.unwrap();
        let epoch1 = user.client.fetch_epoch_history(1, pubkey).await.unwrap();

        assert_eq!(epoch0.verify_sig(&pubkey), Ok(()));
        assert_eq!(epoch0.verify_hash(&None), Ok(()));
        assert_eq!(epoch1.verify_hash(&Some(epoch0)), Ok(()));
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_single_peer() -> Result<()> {
    test(4, |fed, user, bitcoin, _, _| async move {
        bitcoin.mine_blocks(110);
        fed.run_consensus_epochs(1).await;

        // Keep peer 3 out of consensus
        let online_peers = fed.subset_peers(&[0, 1, 2]);
        let peer3 = fed.subset_peers(&[3]);
        bitcoin.mine_blocks(100);
        online_peers.run_consensus_epochs(1).await;
        bitcoin.mine_blocks(100);
        online_peers.run_consensus_epochs(1).await;
        let height = user.client.await_consensus_block_height(0).await.unwrap();

        // Run until peer 3 has rejoined
        join_all(vec![
            Either::Left(async {
                online_peers.await_consensus_epochs(11).await.unwrap();
            }),
            Either::Right(async {
                peer3.rejoin_consensus().await.unwrap();
                peer3.await_consensus_epochs(1).await.unwrap();
            }),
        ])
        .await;

        // Ensure peer 3 rejoined and caught up to consensus
        let client2 = user.new_user_with_peers(peers(&[1, 2, 3])).await;

        let new_height = client2
            .client
            .await_consensus_block_height(height)
            .await
            .unwrap();
        assert_eq!(new_height, height);
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_threshold_peers() -> Result<()> {
    test(2, |fed, _user, bitcoin, _, _| async move {
        bitcoin.mine_blocks(110);
        fed.run_consensus_epochs(1).await;
        fed.rejoin_consensus().await.unwrap();
        fed.await_consensus_epochs(1).await.unwrap();
        bitcoin.mine_blocks(100);
        fed.run_consensus_epochs(1).await;
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_recovered() -> Result<()> {
    test(2, |fed, user_send, bitcoin, _, _| async move {
        let user_receive = user_send.new_user_with_peers(peers(&[0, 1, 2])).await;

        fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
        assert_eq!(user_send.total_notes().await, sats(5000));
        assert_eq!(user_receive.total_notes().await, sats(0));

        user_send
            .client
            .mint_client()
            .back_up_ecash_to_federation()
            .await
            .unwrap();

        user_send.client.mint_client().wipe_notes().await.unwrap();

        user_send.assert_total_notes(sats(0)).await;

        let mut task_group = TaskGroup::new();

        user_send
            .client
            .mint_client()
            .restore_ecash_from_federation(10, &mut task_group)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(user_send.total_notes().await, sats(5000));

        let ecash = fed.spend_ecash(&user_send, sats(3500)).await;
        user_receive.client.reissue(ecash, rng()).await.unwrap();
        fed.run_consensus_epochs(2).await; // process transaction + sign new notes

        user_send
            .client
            .mint_client()
            .restore_ecash_from_federation(10, &mut task_group)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_send.total_notes().await, sats(1500));

        // Generate a lot of epochs, to test multi-threaded fetching
        // and possibly other things that come with more epochs to
        // process.
        for _ in 0..10 {
            let ecash = fed.spend_ecash(&user_send, sats(10)).await;
            user_receive.client.reissue(ecash, rng()).await.unwrap();
            fed.run_consensus_epochs(2).await; // process transaction + sign new notes
        }

        user_send
            .client
            .mint_client()
            .restore_ecash_from_federation(10, &mut task_group)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_send.total_notes().await, sats(1400));

        task_group.join_all(None).await.unwrap();
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn verifies_client_configs() -> Result<()> {
    test(2, |fed, user, bitcoin, _, _| async move {
        bitcoin.mine_blocks(100);

        // fed needs to run an epoch to combine shares
        let id = user.client.config().0.federation_id.clone();
        let res = user.client.verify_config(&id).await;
        assert_matches!(
            res,
            Err(ClientError::ConfigVerify(ConfigVerifyError::Unsigned))
        );

        fed.run_consensus_epochs(1).await;
        let res = user.client.verify_config(&id).await;
        assert!(res.is_ok());
    })
    .await
}

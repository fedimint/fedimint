mod fixtures;

use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin::{Amount, KeyPair};
use fixtures::{fixtures, rng, sats, secp, sha256};
use futures::executor::block_on;
use futures::future::{join_all, Either};
use threshold_crypto::{SecretKey, SecretKeyShare};

use crate::fixtures::FederationTest;
use minimint::consensus::ConsensusItem;
use minimint::transaction::Output;
use minimint_api::OutPoint;
use minimint_ln::contracts::incoming::PreimageDecryptionShare;
use minimint_ln::DecryptionShareCI;
use minimint_mint::tiered::coins::Coins;
use minimint_mint::{PartialSigResponse, PartiallySignedRequest};
use minimint_wallet::WalletConsensusItem;
use minimint_wallet::WalletConsensusItem::PegOutSignature;
use mint_client::clients::transaction::TransactionBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_and_peg_out_with_fees() {
    const PEG_IN_AMOUNT: u64 = 5000;
    const PEG_OUT_AMOUNT: u64 = 1200; // amount requires minted change

    let (fed, user, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    let after_peg_in = sats(PEG_IN_AMOUNT) - fed.fees.fee_peg_in_abs;
    let after_peg_out = after_peg_in - sats(PEG_OUT_AMOUNT) - fed.fees.fee_peg_out_abs;

    let peg_in_address = user.client.get_new_pegin_address(rng());
    let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(PEG_IN_AMOUNT));
    bitcoin.mine_blocks(fed.wallet.finalty_delay as u64);
    fed.run_consensus_epochs(1).await;

    user.client.peg_in(proof, tx, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // peg in epoch + partial sigs epoch
    user.assert_total_coins(after_peg_in).await;

    let peg_out_address = bitcoin.get_new_address();
    user.peg_out(PEG_OUT_AMOUNT, &peg_out_address).await;
    fed.run_consensus_epochs(1).await;

    bitcoin.mine_blocks(minimint_wallet::MIN_PEG_OUT_URGENCY as u64 + 1);
    fed.run_consensus_epochs(2).await; // block height epoch + peg out signing epoch
    assert_matches!(
        fed.last_consensus_items().first(),
        Some(ConsensusItem::Wallet(PegOutSignature(_)))
    );

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(PEG_OUT_AMOUNT)
    );
    user.assert_total_coins(after_peg_out).await;
    let fees = fed.fees.fee_peg_in_abs + fed.fees.fee_peg_out_abs;
    assert_eq!(fed.max_balance_sheet(), fees.milli_sat);
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_can_be_exchanged_between_users() {
    let (fed, user_send, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    let user_receive = user_send.new_client(&[0]).await;

    fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
    assert_eq!(user_send.total_coins(), sats(5000));
    assert_eq!(user_receive.total_coins(), sats(0));

    let coins = user_send.client.select_and_spend_coins(sats(3000)).unwrap();
    user_receive.client.reissue(coins, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    user_send.assert_total_coins(sats(2000)).await;
    user_receive.assert_total_coins(sats(3000)).await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_cannot_double_spent_with_different_nodes() {
    let (fed, user1, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    fed.mine_and_mint(&user1, &*bitcoin, sats(5000)).await;
    let coins = user1.client.select_and_spend_coins(sats(2000)).unwrap();

    let (user2, user3) = (user1.new_client(&[0]).await, user1.new_client(&[1]).await);
    let out2 = user2.client.reissue(coins.clone(), rng()).await.unwrap();
    let out3 = user3.client.reissue(coins, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    // FIXME is this the correct behavior, that the first one goes through?
    assert!(user2.client.fetch_coins(out2).await.is_ok());
    assert!(user3.client.fetch_coins(out3).await.is_err());
    assert_eq!(user2.total_coins(), sats(2000));
    assert_eq!(user3.total_coins(), sats(0));
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_in_wallet_can_be_split_into_change() {
    let (fed, user_send, bitcoin, _, _) = fixtures(2, &[sats(100), sats(500)]).await;
    let user_receive = user_send.new_client(&[0]).await;

    fed.mine_and_mint(&user_send, &*bitcoin, sats(1100)).await;
    assert_eq!(
        user_send.coin_amounts(),
        vec![sats(100), sats(500), sats(500)]
    );

    user_receive
        .client
        .receive_coins(sats(400), rng(), |coins| {
            block_on(user_send.client.pay_for_coins(coins, rng())).unwrap()
        });
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    user_receive
        .assert_coin_amounts(vec![sats(100), sats(100), sats(100), sats(100)])
        .await;
    user_send
        .assert_coin_amounts(vec![sats(100), sats(100), sats(500)])
        .await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

async fn drop_peer_3_during_epoch(fed: &FederationTest) {
    // ensure that peers 1,2,3 create an epoch, so they can see peer 3's bad proposal
    fed.subset_peers(&[1, 2, 3]).run_consensus_epochs(1).await;
    fed.subset_peers(&[0]).run_consensus_epochs(1).await;

    // let peers run consensus, but delay peer 0 so if peer 3 wasn't dropped peer 0 won't be included
    join_all(vec![
        Either::Left(fed.subset_peers(&[1, 2]).run_consensus_epochs(1)),
        Either::Right(
            fed.subset_peers(&[0, 3])
                .race_consensus_epoch(vec![Duration::from_millis(500), Duration::from_millis(0)]),
        ),
    ])
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_peg_out_psbts() {
    let (fed, user, bitcoin, _, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    // FIXME coins cannot be fetched if peer is not in the epoch
    fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(3000));
    fed.subset_peers(&[0, 1, 2])
        .mint_coins_for_user(&user, sats(3000))
        .await;
    fed.subset_peers(&[3]).run_consensus_epochs(1).await;

    let peg_out_address = bitcoin.get_new_address();
    user.peg_out(1000, &peg_out_address).await;
    // Ensure peer 0 who received the peg out request is in the next epoch
    fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(1).await;
    fed.subset_peers(&[3]).run_consensus_epochs(1).await;
    bitcoin.mine_blocks(fed.wallet.finalty_delay as u64);
    bitcoin.mine_blocks(minimint_wallet::MIN_PEG_OUT_URGENCY as u64 + 1);
    fed.run_consensus_epochs(1).await;

    fed.subset_peers(&[3]).override_proposal(vec![]);
    drop_peer_3_during_epoch(&fed).await;

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(1000)
    );
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
    assert_eq!(fed.max_balance_sheet(), fed.fees.fee_peg_out_abs.milli_sat);
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_decryption_shares() {
    let (fed, user, bitcoin, gateway, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    let payment_amount = sats(2000);
    // FIXME coins cannot be fetched if peer is not in the epoch
    fed.mine_spendable_utxo(&gateway.user, &*bitcoin, Amount::from_sat(3000));
    fed.subset_peers(&[0, 1, 2])
        .mint_coins_for_user(&gateway.user, sats(3000))
        .await;
    fed.subset_peers(&[3]).run_consensus_epochs(1).await;

    let (keypair, unconfirmed_invoice) = user
        .client
        .create_unconfirmed_invoice(payment_amount, "test description".into(), rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // create offer

    let (_, contract_id) = gateway
        .server
        .buy_preimage_offer(
            unconfirmed_invoice.invoice.payment_hash(),
            &payment_amount,
            rng(),
        )
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // pay for offer

    // propose bad decryption share
    let share = SecretKeyShare::default()
        .decrypt_share_no_verify(&SecretKey::random().public_key().encrypt(""));
    fed.subset_peers(&[3])
        .override_proposal(vec![ConsensusItem::LN(DecryptionShareCI {
            contract_id,
            share: PreimageDecryptionShare(share),
        })]);
    drop_peer_3_during_epoch(&fed).await; // preimage decryption

    user.client
        .claim_incoming_contract(contract_id, keypair, rng())
        .await
        .unwrap();
    fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(2).await; // contract to mint coins, sign coins

    user.assert_total_coins(payment_amount).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_blind_sigs() {
    let (fed, user, bitcoin, _, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000));
    fed.database_add_coins_for_user(&user, sats(2000));

    fed.subset_peers(&[3]).override_proposal(vec![]);
    drop_peer_3_during_epoch(&fed).await;

    user.assert_total_coins(sats(2000)).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_contribute_bad_sigs() {
    let (fed, user, bitcoin, _, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000));
    let out_point = fed.database_add_coins_for_user(&user, sats(2000));
    let bad_proposal = vec![ConsensusItem::Mint(PartiallySignedRequest {
        out_point,
        partial_signature: PartialSigResponse(Coins {
            coins: Default::default(),
        }),
    })];

    fed.subset_peers(&[3]).override_proposal(bad_proposal);
    drop_peer_3_during_epoch(&fed).await;

    user.assert_total_coins(sats(2000)).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_invoice() {
    let (fed, user, bitcoin, gateway, lightning) =
        fixtures(2, &[sats(10), sats(100), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;
    let (contract_id, outpoint) = user
        .client
        .fund_outgoing_ln_contract(&gateway.keys, invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    let contract_account = user
        .client
        .ln_client()
        .get_contract_account(contract_id)
        .await
        .unwrap();
    assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee

    user.client
        .await_outgoing_contract_acceptance(outpoint)
        .await
        .unwrap();

    gateway
        .server
        .pay_invoice(contract_id, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // contract to mint coins, sign coins

    gateway
        .server
        .await_outgoing_contract_claimed(contract_id, outpoint)
        .await
        .unwrap();
    user.assert_total_coins(sats(2000 - 1010)).await;
    gateway.user.assert_total_coins(sats(1010)).await;

    tokio::time::sleep(Duration::from_millis(500)).await; // FIXME need to wait for listfunds to update
    assert_eq!(lightning.amount_sent(), sats(1000));
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_valid_preimage() {
    let starting_balance = sats(2000);
    let payment_amount = sats(100);
    let (fed, user, bitcoin, gateway, _) = fixtures(2, &[sats(1000), sats(100)]).await;
    fed.mine_and_mint(&gateway.user, &*bitcoin, starting_balance)
        .await;
    assert_eq!(user.total_coins(), sats(0));
    assert_eq!(gateway.user.total_coins(), starting_balance);

    // Create invoice and offer in the federation
    let (keypair, unconfirmed_invoice) = user
        .client
        .create_unconfirmed_invoice(payment_amount, "test description".into(), rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // process offer

    // Confirm the offer has been accepted by the federation
    let invoice = user
        .client
        .confirm_invoice(unconfirmed_invoice)
        .await
        .unwrap();

    // Gateway deposits ecash to trigger preimage decryption by the federation
    let (txid, contract_id) = gateway
        .server
        .buy_preimage_offer(invoice.payment_hash(), &payment_amount, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

    // Gateway funds have been escrowed
    gateway
        .user
        .assert_total_coins(starting_balance - payment_amount)
        .await;
    user.assert_total_coins(sats(0)).await;

    // Gateway receives decrypted preimage
    let outpoint = OutPoint { txid, out_idx: 0 };
    let preimage = gateway
        .server
        .await_preimage_decryption(outpoint)
        .await
        .unwrap();

    // Check that the preimage matches user pubkey & lightning invoice preimage
    let pubkey = keypair.public_key();
    assert_eq!(pubkey, preimage.0);
    assert_eq!(&sha256(&pubkey.serialize()), invoice.payment_hash());

    // User claims their ecash
    user.client
        .claim_incoming_contract(contract_id, keypair, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

    // Ecash tokens have been transferred from gateway to user
    gateway
        .user
        .assert_total_coins(starting_balance - payment_amount)
        .await;
    user.assert_total_coins(payment_amount).await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_invalid_preimage() {
    let starting_balance = sats(2000);
    let payment_amount = sats(100);
    let (fed, user, bitcoin, gateway, _) = fixtures(2, &[sats(1000), sats(100)]).await;
    fed.mine_and_mint(&gateway.user, &*bitcoin, starting_balance)
        .await;
    assert_eq!(user.total_coins(), sats(0));
    assert_eq!(gateway.user.total_coins(), starting_balance);

    // Manually construct offer where sha256(preimage) != hash
    let kp = KeyPair::new(&secp(), &mut rng());
    let payment_hash = sha256(&[0]);
    let offer_output = user.client.ln_client().create_offer_output(
        payment_amount,
        payment_hash,
        kp.public_key().serialize(),
    );
    let mut builder = TransactionBuilder::default();
    builder.output(Output::LN(offer_output));
    let tx = builder.build(&secp(), &mut rng());
    fed.submit_transaction(tx);
    fed.run_consensus_epochs(1).await; // process offer

    // Gateway escrows ecash to trigger preimage decryption by the federation
    let (_, contract_id) = gateway
        .server
        .buy_preimage_offer(&payment_hash, &payment_amount, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 for preimage decryption

    // Gateway funds have been escrowed
    gateway
        .user
        .assert_total_coins(starting_balance - payment_amount)
        .await;
    user.assert_total_coins(sats(0)).await;

    // User gets error when they try to claim gateway's escrowed ecash
    let response = user
        .client
        .claim_incoming_contract(contract_id, kp, rng())
        .await;
    assert!(response.is_err());

    // Gateway re-claims their funds
    let _outpoint = gateway
        .client
        .claim_incoming_contract(contract_id, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // 1 epoch to process contract, 1 to sweep ecash from contract

    // Gateway has clawed back their escrowed funds
    gateway.user.assert_total_coins(starting_balance).await;
    user.assert_total_coins(sats(0)).await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_cannot_claim_invalid_preimage() {
    let (fed, user, bitcoin, gateway, lightning) = fixtures(2, &[sats(10), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
    let (contract_id, _) = user
        .client
        .fund_outgoing_ln_contract(&gateway.keys, invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    let bad_preimage: [u8; 32] = rand::random();
    let response = gateway
        .client
        .claim_outgoing_contract(contract_id, bad_preimage, rng())
        .await;
    assert!(response.is_err());

    bitcoin.mine_blocks(100); // create non-empty epoch
    fed.run_consensus_epochs(1).await; // if valid would create contract to mint coins

    fed.last_consensus_items().iter().for_each(|item| {
        assert_matches!(
            item,
            ConsensusItem::Wallet(WalletConsensusItem::RoundConsensus(_))
        )
    });
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lightning_gateway_can_abort_payment_to_return_user_funds() {
    let (fed, user, bitcoin, gateway, lightning) = fixtures(2, &[sats(10), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
    let (contract_id, _) = user
        .client
        .fund_outgoing_ln_contract(&gateway.keys, invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    // FIXME should return funds to user
    gateway.client.abort_outgoing_payment(contract_id);
    fed.run_consensus_epochs(1).await;
    assert_eq!(user.total_coins(), sats(1010));
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_tx_submitted() {
    let (fed, user_send, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    let user_receive = user_send.new_client(&[0]).await;

    fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
    let coins = user_send.client.select_and_spend_coins(sats(5000)).unwrap();

    // If epochs run before the reissue tx, then there won't be any coins to fetch
    join_all(vec![
        Either::Left(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            user_receive.client.reissue(coins, rng()).await.unwrap();
        }),
        Either::Right(fed.run_consensus_epochs(2)),
    ])
    .await;

    user_receive.assert_total_coins(sats(5000)).await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_new_block() {
    let (fed, user, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    fed.mine_and_mint(&user, &*bitcoin, sats(3000)).await;

    let peg_out_address = bitcoin.get_new_address();
    user.peg_out(1000, &peg_out_address).await;
    fed.run_consensus_epochs(1).await;

    // If epochs run before the blocks are mined, won't be able to peg-out
    join_all(vec![
        Either::Left(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            bitcoin.mine_blocks(fed.wallet.finalty_delay as u64);
            bitcoin.mine_blocks(minimint_wallet::MIN_PEG_OUT_URGENCY as u64 + 1);
        }),
        Either::Right(async { fed.run_consensus_epochs(2).await }),
    ])
    .await;

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(1000)
    );
    assert_eq!(fed.max_balance_sheet(), fed.fees.fee_peg_out_abs.milli_sat);
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn audit_negative_balance_sheet_panics() {
    let (fed, user, _, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    fed.mint_coins_for_user(&user, sats(2000)).await;
    fed.run_consensus_epochs(1).await;
}

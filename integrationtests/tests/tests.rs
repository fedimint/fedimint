mod fixtures;

use assert_matches::assert_matches;
use bitcoin::Amount;
use fixtures::fixtures;
use fixtures::{rng, sats};
use futures::executor::block_on;
use minimint::consensus::ConsensusItem;
use minimint_mint::tiered::coins::Coins;
use minimint_mint::{PartialSigResponse, PartiallySignedRequest};
use minimint_wallet::WalletConsensusItem::PegOutSignature;

use std::thread;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_and_peg_out_with_fees() {
    const PEG_IN_AMOUNT: u64 = 5000;
    const PEG_OUT_AMOUNT: u64 = 1200; // amount requires minted change

    let (fed, user, bitcoin, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    let after_peg_in = sats(PEG_IN_AMOUNT) - fed.fee_consensus.fee_peg_in_abs;
    let after_peg_out = after_peg_in - sats(PEG_OUT_AMOUNT) - fed.fee_consensus.fee_peg_out_abs;

    let peg_in_address = user.client.get_new_pegin_address(rng());
    let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(PEG_IN_AMOUNT));
    bitcoin.mine_blocks(fed.wallet.finalty_delay as u64);
    fed.run_consensus_epochs(1).await;

    user.client.peg_in(proof, tx, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // peg in epoch + partial sigs epoch
    user.client.fetch_all_coins().await.unwrap();
    assert_eq!(user.total_coins(), after_peg_in);

    let peg_out_address = bitcoin.get_new_address();
    user.client
        .peg_out(
            Amount::from_sat(PEG_OUT_AMOUNT),
            peg_out_address.clone(),
            rng(),
        )
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await;

    bitcoin.mine_blocks(minimint_wallet::MIN_PEG_OUT_URGENCY as u64 + 1);
    fed.run_consensus_epochs(3).await; // block height epoch + 2 peg out signing epochs
    user.client.fetch_all_coins().await.unwrap();
    assert_matches!(
        fed.last_consensus_items().first(),
        Some(ConsensusItem::Wallet(PegOutSignature(_)))
    );

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(PEG_OUT_AMOUNT)
    );
    assert_eq!(user.total_coins(), after_peg_out);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn peg_out_with_p2pkh() {
    // FIXME Hash of peg-out transaction doesn't match in wallet and fed code, causing InvalidSignature error
    let (fed, user, _, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    fed.mint_coins_for_user(&user, sats(4500)).await;

    let ctx = bitcoin::secp256k1::Secp256k1::new();
    let (_, public_key) = ctx.generate_keypair(&mut rng());
    let peg_out_address = bitcoin::Address::p2pkh(
        &bitcoin::ecdsa::PublicKey::new(public_key),
        bitcoin::Network::Regtest,
    );
    user.client
        .peg_out(Amount::from_sat(1000), peg_out_address.clone(), rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_can_be_exchanged_between_users() {
    let (fed, user_send, _, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    let user_receive = user_send.new_client(&[0]);

    fed.mint_coins_for_user(&user_send, sats(5000)).await;
    assert_eq!(user_send.total_coins(), sats(5000));
    assert_eq!(user_receive.total_coins(), sats(0));

    let coins = user_send.client.select_and_spend_coins(sats(3000)).unwrap();
    let outpoint = user_receive.client.reissue(coins, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    user_receive.client.fetch_coins(outpoint).await.unwrap();
    assert_eq!(user_send.total_coins(), sats(2000));
    assert_eq!(user_receive.total_coins(), sats(3000));
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_cannot_double_spent_with_different_nodes() {
    let (fed, user1, _, _, _) = fixtures(2, &[sats(100), sats(1000)]).await;
    fed.mint_coins_for_user(&user1, sats(5000)).await;
    let coins = user1.client.select_and_spend_coins(sats(2000)).unwrap();

    let (user2, user3) = (user1.new_client(&[0]), user1.new_client(&[1]));
    let out2 = user2.client.reissue(coins.clone(), rng()).await.unwrap();
    let out3 = user3.client.reissue(coins, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    // FIXME is this the correct behavior, that the first one goes through?
    assert!(user2.client.fetch_coins(out2).await.is_ok());
    assert!(user3.client.fetch_coins(out3).await.is_err());
    assert_eq!(user2.total_coins(), sats(2000));
    assert_eq!(user3.total_coins(), sats(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn minted_coins_in_wallet_can_be_split_into_change() {
    let (fed, user_send, _, _, _) = fixtures(2, &[sats(100), sats(500)]).await;
    let user_receive = user_send.new_client(&[0]);

    fed.mint_coins_for_user(&user_send, sats(1100)).await;
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
    user_receive.client.fetch_all_coins().await.unwrap();
    user_send.client.fetch_all_coins().await.unwrap();
    assert_eq!(
        user_receive.coin_amounts(),
        vec![sats(100), sats(100), sats(100), sats(100)]
    );
    assert_eq!(
        user_send.coin_amounts(),
        vec![sats(100), sats(100), sats(500)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_blind_sigs() {
    let (fed, user, _, _, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    fed.database_add_coins_for_user(&user, sats(1000));

    // process epoch with peer #3 not contributing blind sigs
    fed.subset_peers(&[3]).override_proposal(vec![]);
    fed.subset_peers(&[1, 2, 3]).run_consensus_epochs(1).await;

    // peers drop #3 and do not process its proposal, instead wait for peer #0
    fed.subset_peers(&[1, 2, 3]).send_proposals();
    thread::sleep(Duration::from_millis(500));
    fed.subset_peers(&[0]).run_consensus_epochs(2).await;
    fed.subset_peers(&[0]).send_proposals();

    user.client.fetch_all_coins().await.unwrap();
    assert_eq!(user.total_coins(), sats(1000));
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_contribute_bad_sigs() {
    let (fed, user, _, _, _) = fixtures(4, &[sats(100), sats(1000)]).await;
    let out_point = fed.database_add_coins_for_user(&user, sats(1000));
    let bad_proposal = vec![ConsensusItem::Mint(PartiallySignedRequest {
        out_point,
        partial_signature: PartialSigResponse(Coins {
            coins: Default::default(),
        }),
    })];

    // process epoch with peer #3 contributing bad sigs
    fed.subset_peers(&[3]).override_proposal(bad_proposal);
    fed.subset_peers(&[1, 2, 3]).run_consensus_epochs(1).await;

    // peers drop #3 and do not process its proposal, instead wait for peer #0
    fed.subset_peers(&[1, 2, 3]).send_proposals();
    thread::sleep(Duration::from_millis(500));
    fed.subset_peers(&[0]).run_consensus_epochs(2).await;
    fed.subset_peers(&[0]).send_proposals();

    user.client.fetch_all_coins().await.unwrap();
    assert_eq!(user.total_coins(), sats(1000));
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_invoice() {
    let (fed, user, _, gateway, lightning) = fixtures(2, &[sats(10), sats(100), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mint_coins_for_user(&user, sats(2000)).await;
    let contract_id = user
        .client
        .fund_outgoing_ln_contract(&gateway.keys, invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    let contract_account = user.client.wait_contract(contract_id).await.unwrap();
    assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee
    gateway
        .server
        .pay_invoice(contract_id, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // contract to mint coins, sign coins

    gateway.server.await_contract_claimed(contract_id).await;
    user.client.fetch_all_coins().await.unwrap();
    assert_eq!(user.total_coins(), sats(2000 - 1010));
    assert_eq!(gateway.user_client.coins().amount(), sats(1010));
    assert_eq!(lightning.amount_sent(), sats(1000));
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_cannot_claim_invalid_preimage() {
    let (fed, user, _, gateway, lightning) = fixtures(2, &[sats(10), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mint_coins_for_user(&user, sats(1010)).await; // 1% LN fee
    let contract_id = user
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

    fed.run_consensus_epochs(1).await; // if valid would create contract to mint coins
    assert!(fed.last_consensus_items().is_empty())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn lightning_gateway_can_abort_payment_to_return_user_funds() {
    let (fed, user, _, gateway, lightning) = fixtures(2, &[sats(10), sats(1000)]).await;
    let invoice = lightning.invoice(sats(1000));

    fed.mint_coins_for_user(&user, sats(1010)).await; // 1% LN fee
    let contract_id = user
        .client
        .fund_outgoing_ln_contract(&gateway.keys, invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    // FIXME should return funds to user
    gateway.client.abort_outgoing_payment(contract_id);
    fed.run_consensus_epochs(1).await;
    assert_eq!(user.total_coins(), sats(1010));
}

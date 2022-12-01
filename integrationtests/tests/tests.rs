mod fixtures;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use assert_matches::assert_matches;
use bitcoin::{Amount, KeyPair};
use fedimint_api::cancellable::Cancellable;
use fedimint_api::core::MODULE_KEY_LN;
use fedimint_api::db::mem_impl::MemDatabase;
use fedimint_api::TieredMulti;
use fedimint_ln::contracts::{Preimage, PreimageDecryptionShare};
use fedimint_ln::LightningConsensusItem;
use fedimint_mint::config::MintClientConfig;
use fedimint_mint::{MintOutputConfirmation, OutputConfirmationSignatures};
use fedimint_server::all_decoders;
use fedimint_server::epoch::ConsensusItem;
use fedimint_server::transaction::legacy::Output;
use fedimint_wallet::PegOutSignatureItem;
use fedimint_wallet::WalletConsensusItem::PegOutSignature;
use fixtures::{fixtures, rng, sats, secp, sha256, Fixtures};
use futures::future::{join_all, Either};
use mint_client::transaction::TransactionBuilder;
use mint_client::ClientError;
use threshold_crypto::{SecretKey, SecretKeyShare};
use tokio::time::timeout;
use tracing::debug;

use crate::fixtures::{assert_ci, create_user_client, peers, FederationTest, UserTest};

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_and_peg_out_with_fees() -> anyhow::Result<()> {
    let peg_in_amount: u64 = 5000;
    let peg_out_amount: u64 = 1200; // amount requires minted change
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;

    let peg_in_address = user.client.get_new_pegin_address(rng()).await;
    let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(peg_in_amount));
    bitcoin.mine_blocks(fed.wallet.finality_delay as u64);
    fed.run_consensus_epochs(1).await;

    user.client.peg_in(proof, tx, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // peg in epoch + partial sigs epoch
    user.assert_total_coins(sats(peg_in_amount)).await;

    let peg_out_address = bitcoin.get_new_address();
    let (fees, out_point) = user.peg_out(peg_out_amount, &peg_out_address).await;
    fed.run_consensus_epochs(2).await; // peg-out tx + peg out signing epoch

    assert_matches!(
        assert_ci(fed.last_consensus_items().first().unwrap()),
        PegOutSignature(_)
    );

    let outcome_txid = user
        .client
        .wallet_client()
        .await_peg_out_outcome(out_point)
        .await
        .unwrap();
    assert!(matches!(
            assert_ci(fed.last_consensus_items().first().unwrap()), 
            PegOutSignature(PegOutSignatureItem {
                txid,
                ..
            }) if *txid == outcome_txid));

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(peg_out_amount)
    );
    user.assert_total_coins(sats(peg_in_amount - peg_out_amount) - fees)
        .await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_are_rejected_if_fees_are_too_low() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;
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

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_are_only_allowed_once_per_epoch() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;
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
    user.client.reissue_pending_coins(rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // reissue the coins from the tx that failed
    user.assert_total_coins(sats(5000 - 1000) - fees).await;

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_must_wait_for_available_utxos() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;
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

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_can_be_exchanged_directly_between_users() -> Result<()> {
    let Fixtures {
        fed,
        user: user_send,
        bitcoin,
        task_group,
        ..
    } = fixtures(4, &[sats(10), sats(100), sats(1000)]).await?;

    let user_receive = UserTest::new(Arc::new(
        create_user_client(
            user_send.config.clone(),
            peers(&[0, 1, 2]),
            MemDatabase::new().into(),
        )
        .await,
    ));

    fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
    assert_eq!(user_send.total_coins(), sats(5000));
    assert_eq!(user_receive.total_coins(), sats(0));

    let ecash = fed.spend_ecash(&user_send, sats(3500)).await;
    user_receive.client.reissue(ecash, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    user_send.assert_total_coins(sats(1500)).await;
    user_receive.assert_total_coins(sats(3500)).await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_cannot_double_spent_with_different_nodes() -> Result<()> {
    let Fixtures {
        fed,
        user: user1,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;
    fed.mine_and_mint(&user1, &*bitcoin, sats(5000)).await;
    let ecash = fed.spend_ecash(&user1, sats(2000)).await;

    let cfg = user1.config.clone();
    let user2 = UserTest::new(Arc::new(
        create_user_client(cfg.clone(), peers(&[0]), MemDatabase::new().into()).await,
    ));
    let user3 = UserTest::new(Arc::new(
        create_user_client(cfg, peers(&[1]), MemDatabase::new().into()).await,
    ));

    let out2 = user2.client.reissue(ecash.clone(), rng()).await.unwrap();
    let out3 = user3.client.reissue(ecash, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    let res2 = user2.client.fetch_coins(out2).await;
    let res3 = user3.client.fetch_coins(out3).await;
    assert!(res2.is_err() || res3.is_err()); //no double spend
    assert_eq!(user2.total_coins() + user3.total_coins(), sats(2000));
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn ecash_in_wallet_can_sent_through_a_tx() -> Result<()> {
    let Fixtures {
        fed,
        user: user_send,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(500)]).await?;

    let user_receive = UserTest::new(Arc::new(
        create_user_client(
            user_send.config.clone(),
            peers(&[0]),
            MemDatabase::new().into(),
        )
        .await,
    ));

    fed.mine_and_mint(&user_send, &*bitcoin, sats(1100)).await;
    assert_eq!(
        user_send.coin_amounts(),
        vec![sats(100), sats(500), sats(500)]
    );

    user_receive
        .client
        .receive_coins(sats(400), |coins| async {
            user_send
                .client
                .pay_to_blind_nonces(coins, rng())
                .await
                .unwrap()
        })
        .await;

    fed.run_consensus_epochs(2).await; // process transaction + sign new coins

    user_receive
        .assert_coin_amounts(vec![sats(100), sats(100), sats(100), sats(100)])
        .await;
    user_send
        .assert_coin_amounts(vec![sats(100), sats(100), sats(500)])
        .await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

async fn drop_peer_3_during_epoch(fed: &FederationTest) -> Cancellable<()> {
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
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(4, &[sats(1), sats(10), sats(100), sats(1000)]).await?;
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

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_decryption_shares() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        task_group,
        ..
    } = fixtures(4, &[sats(100), sats(1000)]).await?;
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
            LightningConsensusItem {
                contract_id,
                share: PreimageDecryptionShare(share),
            }
            .into(),
        )]);
    drop_peer_3_during_epoch(&fed).await.unwrap(); // preimage decryption

    user.client
        .claim_incoming_contract(contract_id, rng())
        .await
        .unwrap();
    fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(2).await; // contract to mint coins, sign coins

    user.assert_total_coins(payment_amount).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_dont_contribute_blind_sigs() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(4, &[sats(100), sats(1000)]).await?;
    fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000))
        .await;
    fed.database_add_coins_for_user(&user, sats(2000)).await;

    fed.subset_peers(&[3]).override_proposal(vec![]);
    drop_peer_3_during_epoch(&fed).await.unwrap();

    user.assert_total_coins(sats(2000)).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_peers_who_contribute_bad_sigs() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(4, &[sats(100), sats(1000)]).await?;
    fed.mine_spendable_utxo(&user, &*bitcoin, Amount::from_sat(2000))
        .await;
    let out_point = fed.database_add_coins_for_user(&user, sats(2000)).await;
    let bad_proposal = vec![ConsensusItem::Module(
        MintOutputConfirmation {
            out_point,
            signatures: OutputConfirmationSignatures(TieredMulti::default()),
        }
        .into(),
    )];

    fed.subset_peers(&[3]).override_proposal(bad_proposal);
    drop_peer_3_during_epoch(&fed).await.unwrap();

    user.assert_total_coins(sats(2000)).await;
    assert!(fed.subset_peers(&[0, 1, 2]).has_dropped_peer(3));

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_internal_invoice() -> Result<()> {
    let Fixtures {
        fed,
        user: sending_user,
        bitcoin,
        gateway,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;

    // Fund the gateway so it can route internal payments
    fed.mine_and_mint(&gateway.user, &*bitcoin, sats(2000))
        .await;
    fed.mine_and_mint(&sending_user, &*bitcoin, sats(2000))
        .await;

    let receiving_user = UserTest::new(Arc::new(
        create_user_client(
            sending_user.config.clone(),
            peers(&[0]),
            MemDatabase::new().into(),
        )
        .await,
    ));

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

    let (contract_id, funding_outpoint) = sending_user
        .client
        .fund_outgoing_ln_contract(invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // send coins to LN contract

    let contract_account = sending_user
        .client
        .ln_client()
        .get_contract_account(contract_id)
        .await
        .unwrap();
    assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee
    debug!(
        "Sending User created outgoing contract: {:?}",
        contract_account
    );

    sending_user
        .client
        .await_outgoing_contract_acceptance(funding_outpoint)
        .await
        .unwrap();
    debug!("Outgoing contract accepted");

    let claim_outpoint = tokio::join!(
        gateway
            .actor
            .pay_invoice(gateway.adapter.clone(), contract_id),
        async {
            // buy preimage from offer, decrypt preimage, claim outgoing contract, mint the tokens
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
    fed.run_consensus_epochs(2).await; // claim incoming contract and mint the tokens

    receiving_user
        .client
        .fetch_coins(receiving_outpoint)
        .await
        .unwrap();
    debug!("User fetched funds paid to incoming contract");

    sending_user.assert_total_coins(sats(2000 - 1010)).await; // user sent a 1000 sat + 10 sat fee invoice
    gateway.user.assert_total_coins(sats(2010)).await; // gateway routed internally and earned fee
    receiving_user.assert_total_coins(sats(1000)).await; // this user received the 1000 sat invoice

    assert_eq!(lightning.amount_sent().await, sats(0)); // We did not route any payments over the lightning network
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_outgoing_invoice() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;
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
    fed.run_consensus_epochs(2).await; // contract to mint coins, sign coins

    gateway
        .actor
        .await_outgoing_contract_claimed(contract_id, claim_outpoint)
        .await
        .unwrap();
    user.assert_total_coins(sats(2000 - 1010)).await;
    gateway.user.assert_total_coins(sats(1010)).await;

    tokio::time::sleep(Duration::from_millis(500)).await; // FIXME need to wait for listfunds to update
    assert_eq!(lightning.amount_sent().await, sats(1000));
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_claims_refund_for_internal_invoice() -> Result<()> {
    let Fixtures {
        fed,
        user: sending_user,
        bitcoin,
        gateway,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(100), sats(1000)]).await?;

    // Fund the gateway so it can route internal payments
    fed.mine_and_mint(&gateway.user, &*bitcoin, sats(2000))
        .await;
    fed.mine_and_mint(&sending_user, &*bitcoin, sats(2000))
        .await;

    let receiving_client = create_user_client(
        sending_user.config.clone(),
        peers(&[0]),
        MemDatabase::new().into(),
    )
    .await;

    let confirmed_invoice = tokio::join!(
        receiving_client.generate_invoice(sats(1000), "".into(), rng(), None),
        fed.await_consensus_epochs(1),
    )
    .0
    .unwrap();
    let invoice = confirmed_invoice.invoice;
    debug!("Receiving User generated invoice: {:?}", invoice);

    let (contract_id, funding_outpoint) = sending_user
        .client
        .fund_outgoing_ln_contract(invoice, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(2).await; // send coins to LN contract

    let contract_account = sending_user
        .client
        .ln_client()
        .get_contract_account(contract_id)
        .await
        .unwrap();
    assert_eq!(contract_account.amount, sats(1010)); // 1% LN fee
    debug!(
        "Sending User created outgoing contract: {:?}",
        contract_account
    );

    sending_user
        .client
        .await_outgoing_contract_acceptance(funding_outpoint)
        .await
        .unwrap();
    debug!("Outgoing contract accepted");

    let response = tokio::join!(
        gateway
            .actor
            .pay_invoice(gateway.adapter.clone(), contract_id),
        async {
            // we should run 4 epocks to buy preimage from offer, decrypt preimage, claim outgoing contract, mint the tokens
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

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn set_lightning_invoice_expiry() -> Result<()> {
    let Fixtures {
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(1000)]).await?;
    let invoice = lightning.invoice(sats(1000), 600.into());
    assert_eq!(invoice.await.expiry_time(), Duration::from_secs(600));

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_valid_preimage() -> Result<()> {
    let starting_balance = sats(2000);
    let preimage_price = sats(100);
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        task_group,
        ..
    } = fixtures(2, &[sats(1000), sats(100)]).await?;
    fed.mine_and_mint(&gateway.user, &*bitcoin, starting_balance)
        .await;
    assert_eq!(user.total_coins(), sats(0));
    assert_eq!(gateway.user.total_coins(), starting_balance);

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
        .assert_total_coins(starting_balance - preimage_price)
        .await;
    user.assert_total_coins(sats(0)).await;

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

    // Ecash tokens have been transferred from gateway to user
    gateway
        .user
        .assert_total_coins(starting_balance - preimage_price)
        .await;
    user.assert_total_coins(preimage_price).await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn receive_lightning_payment_invalid_preimage() -> Result<()> {
    let starting_balance = sats(2000);
    let payment_amount = sats(100);
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        task_group,
        ..
    } = fixtures(2, &[sats(1000), sats(100)]).await?;
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
        Preimage(kp.x_only_public_key().0.serialize()),
        None,
    );
    let mut builder = TransactionBuilder::default();
    builder.output(Output::LN(offer_output));
    let tbs_pks = &user
        .config
        .0
        .get_module::<MintClientConfig>("mint")?
        .tbs_pks;
    let context = &user.client.mint_client().context;
    let mut dbtx = context.db.begin_transaction(all_decoders());
    let tx = builder
        .build(
            sats(0),
            &mut dbtx,
            || async { user.client.mint_client().new_ecash_note(&secp()).await },
            &secp(),
            tbs_pks,
            rng(),
        )
        .await;
    fed.submit_transaction(tx.into_type_erased());
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
        .assert_total_coins(starting_balance - payment_amount)
        .await;
    user.assert_total_coins(sats(0)).await;

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
    gateway.user.assert_total_coins(starting_balance).await;
    user.assert_total_coins(sats(0)).await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_cannot_claim_invalid_preimage() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(1000)]).await?;
    let invoice = lightning.invoice(sats(1000), None);

    fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
    let (contract_id, _) = user
        .client
        .fund_outgoing_ln_contract(invoice.await, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

    // Create a random preimage that has no association to the contract invoice
    let rand_slice: [u8; 32] = rand::random();
    let bad_preimage = Preimage(rand_slice);
    let response = gateway
        .client
        .claim_outgoing_contract(contract_id, bad_preimage, rng())
        .await;
    assert!(response.is_err());

    bitcoin.mine_blocks(100); // create non-empty epoch
    fed.run_consensus_epochs(1).await; // if valid would create contract to mint coins

    let ln_items = fed
        .last_consensus_items()
        .iter()
        .filter(|item| match item {
            ConsensusItem::Module(mci) => mci.module_key() == MODULE_KEY_LN,
            _ => false,
        })
        .count();
    assert_eq!(ln_items, 0);
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_can_abort_payment_to_return_user_funds() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        gateway,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(10), sats(1000)]).await?;
    let invoice = lightning.invoice(sats(1000), None);

    fed.mine_and_mint(&user, &*bitcoin, sats(1010)).await; // 1% LN fee
    let (contract_id, _) = user
        .client
        .fund_outgoing_ln_contract(invoice.await, rng())
        .await
        .unwrap();
    fed.run_consensus_epochs(1).await; // send coins to LN contract

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
    user.client.fetch_coins(outpoint).await.unwrap();
    assert_eq!(user.total_coins(), sats(1010));
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_tx_submitted() -> Result<()> {
    let Fixtures {
        fed,
        user: user_send,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;

    let user_receive = UserTest::new(Arc::new(
        create_user_client(
            user_send.config.clone(),
            peers(&[0]),
            MemDatabase::new().into(),
        )
        .await,
    ));

    fed.mine_and_mint(&user_send, &*bitcoin, sats(5000)).await;
    let ecash = fed.spend_ecash(&user_send, sats(5000)).await;

    // If epochs run before the reissue tx, then there won't be any coins to fetch
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

    user_receive.assert_total_coins(sats(5000)).await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_consensus_if_new_block() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;
    let peg_in_address = user.client.get_new_pegin_address(rng()).await;
    bitcoin.mine_blocks(100);
    let (proof, tx) = bitcoin.send_and_mine_block(&peg_in_address, Amount::from_sat(1000));
    fed.run_consensus_epochs(1).await;

    // If epochs run before the blocks are mined, user won't be able to peg-in
    join_all(vec![
        Either::Left(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            bitcoin.mine_blocks(fed.wallet.finality_delay as u64);
        }),
        Either::Right(async { fed.await_consensus_epochs(1).await.unwrap() }),
    ])
    .await;

    user.client.peg_in(proof, tx, rng()).await.unwrap();
    fed.run_consensus_epochs(2).await; // peg-in + blind sign
    user.assert_total_coins(sats(1000)).await;
    assert_eq!(fed.max_balance_sheet(), 0);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
#[should_panic]
async fn audit_negative_balance_sheet_panics() {
    if let Ok(Fixtures {
        fed,
        user,
        task_group,
        ..
    }) = fixtures(2, &[sats(100), sats(1000)]).await
    {
        fed.mint_coins_for_user(&user, sats(2000)).await;
        fed.run_consensus_epochs(1).await;
        task_group.shutdown_join_all().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unbalanced_transactions_get_rejected() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        lightning,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;
    // cannot make change for this invoice (results in unbalanced tx)
    let invoice = lightning.invoice(sats(777), None);

    fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;
    let response = user
        .client
        .fund_outgoing_ln_contract(invoice.await, rng())
        .await;

    // TODO return a more useful error
    assert!(response.is_err());

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_have_federations_with_one_peer() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(1, &[sats(100), sats(1000)]).await?;
    fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;
    user.assert_total_coins(sats(1000)).await;

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn can_get_signed_epoch_history() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;

    fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;
    fed.mine_and_mint(&user, &*bitcoin, sats(1000)).await;

    let pubkey = fed.cfg.epoch_pk_set.public_key();
    let epoch0 = user.client.fetch_epoch_history(0, pubkey).await.unwrap();
    let epoch1 = user.client.fetch_epoch_history(1, pubkey).await.unwrap();

    assert_eq!(epoch0.verify_sig(&pubkey), Ok(()));
    assert_eq!(epoch0.verify_hash(&None), Ok(()));
    assert_eq!(epoch1.verify_hash(&Some(epoch0)), Ok(()));

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_single_peer() -> Result<()> {
    let Fixtures {
        fed,
        user,
        bitcoin,
        task_group,
        ..
    } = fixtures(4, &[sats(100), sats(1000)]).await?;

    // Keep peer 3 out of consensus
    bitcoin.mine_blocks(110);
    fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(1).await;
    bitcoin.mine_blocks(100);
    fed.subset_peers(&[0, 1, 2]).run_consensus_epochs(1).await;
    let height = user.client.await_consensus_block_height(0).await?;

    join_all(vec![
        Either::Left(async {
            fed.subset_peers(&[0, 1, 2])
                .await_consensus_epochs(1)
                .await
                .unwrap();
        }),
        Either::Right(async {
            fed.subset_peers(&[3]).rejoin_consensus().await.unwrap();
        }),
    ])
    .await;

    // Ensure peer 3 rejoined and caught up to consensus
    let client2 = create_user_client(
        user.config.clone(),
        peers(&[1, 2, 3]),
        MemDatabase::new().into(),
    )
    .await;

    assert_eq!(client2.await_consensus_block_height(height).await?, height);

    task_group.shutdown_join_all().await
}

#[tokio::test(flavor = "multi_thread")]
async fn rejoin_consensus_threshold_peers() -> Result<()> {
    let Fixtures {
        fed,
        bitcoin,
        task_group,
        ..
    } = fixtures(2, &[sats(100), sats(1000)]).await?;
    let peer0 = fed.subset_peers(&[0]);
    let peer1 = fed.subset_peers(&[1]);

    bitcoin.mine_blocks(110);
    fed.run_consensus_epochs(1).await;

    let rejoin = join_all(vec![
        Either::Left(async {
            peer0.rejoin_consensus().await.unwrap();
        }),
        Either::Right(async {
            peer1.rejoin_consensus().await.unwrap();
        }),
    ]);

    // confirm that the entire federation can rejoin at an epoch
    timeout(Duration::from_secs(15), rejoin).await.unwrap();

    task_group.shutdown_join_all().await
}

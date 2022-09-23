mod fixtures;

use std::time::Duration;

use assert_matches::assert_matches;
use bitcoin::{Amount, KeyPair};

use fixtures::{rng, sats, secp, sha256};
use futures::executor::block_on;
use futures::future::{join_all, Either};
use threshold_crypto::{SecretKey, SecretKeyShare};
use tokio::time::timeout;
use tracing::debug;

use crate::fixtures::{FederationTest, Fixtures};
use fedimint::epoch::ConsensusItem;
use fedimint::transaction::Output;
use fedimint_api::db::batch::DbBatch;
use fedimint_ln::contracts::incoming::PreimageDecryptionShare;
use fedimint_ln::DecryptionShareCI;
use fedimint_mint::tiered::TieredMulti;
use fedimint_mint::{PartialSigResponse, PartiallySignedRequest};
use fedimint_wallet::PegOutSignatureItem;
use fedimint_wallet::WalletConsensusItem::PegOutSignature;
use mint_client::transaction::TransactionBuilder;
use mint_client::ClientError;

#[tokio::test(flavor = "multi_thread")]
async fn peg_in_and_peg_out_with_fees() {
    let peg_in_amount: u64 = 5000;
    let peg_out_amount: u64 = 1200; // amount requires minted change
    let (fed, user, bitcoin) = Fixtures::new(2, &[sats(10), sats(100), sats(1000)])
        .build()
        .await;

    let peg_in_address = user.client.get_new_pegin_address(rng());
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
        fed.last_consensus_items().first(),
        Some(ConsensusItem::Wallet(PegOutSignature(_)))
    );

    let outcome_txid = user
        .client
        .wallet_client()
        .await_peg_out_outcome(out_point)
        .await
        .unwrap();
    assert!(matches!(
            fed.last_consensus_items().first(), 
            Some(ConsensusItem::Wallet(PegOutSignature(PegOutSignatureItem {
                txid,
             ..
            }))) if *txid == outcome_txid));

    fed.broadcast_transactions().await;
    assert_eq!(
        bitcoin.mine_block_and_get_received(&peg_out_address),
        sats(peg_out_amount)
    );
    user.assert_total_coins(sats(peg_in_amount - peg_out_amount) - fees)
        .await;
    assert_eq!(fed.max_balance_sheet(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn lightning_gateway_pays_outgoing_invoice() {
    let (fed, user, bitcoin, gateway, lightning, _) =
        Fixtures::new(2, &[sats(10), sats(100), sats(1000)])
            .build_all()
            .await;
    let invoice = lightning.invoice(sats(1000));

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
async fn test_ln_client_adapter() {
    let (fed, user, bitcoin, gateway, lightning, ln_client_adapter) =
        Fixtures::new(2, &[sats(10), sats(100), sats(1000)])
            .build_all()
            .await;

    let invoice = lightning.invoice(sats(1000));

    fed.mine_and_mint(&user, &*bitcoin, sats(2000)).await;
    let (contract_id, outpoint) = user
        .client
        .fund_outgoing_ln_contract(invoice.clone(), rng())
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

    //tell the ln_client that is contained in the gateway to fail two times for that invoice
    ln_client_adapter.fail_until(invoice.to_string(), 3).await;
    assert!(gateway
        .server
        .pay_invoice(contract_id.clone(), rng())
        .await
        .is_err());
    assert!(gateway
        .server
        .pay_invoice(contract_id.clone(), rng())
        .await
        .is_err());
    gateway
        .server
        .pay_invoice(contract_id.clone(), rng())
        .await
        .unwrap();
}

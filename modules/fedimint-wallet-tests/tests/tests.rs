use std::collections::HashSet;
use std::env;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use assert_matches::assert_matches;
use bitcoin::secp256k1;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_client::ClientHandleArc;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{DatabaseTransaction, IRawDatabaseExt};
use fedimint_core::module::{AmountUnit, serde_json};
use fedimint_core::task::{TaskGroup, sleep_in_test};
use fedimint_core::util::{BoxStream, NextOrPending, SafeUrl, retry};
use fedimint_core::{Amount, BitcoinHash, Feerate, InPoint, PeerId, TransactionId, sats};
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_server::core::ServerModule;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::envs::{FM_TEST_BACKEND_BITCOIN_RPC_KIND_ENV, FM_TEST_USE_REAL_DAEMONS_ENV};
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_testing_core::config::API_AUTH;
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{DepositStateV2, WalletClientInit, WalletClientModule, WithdrawState};
use fedimint_wallet_common::config::WalletConfig;
use fedimint_wallet_common::tweakable::Tweakable;
use fedimint_wallet_common::txoproof::PegInProof;
use fedimint_wallet_common::{PegOutFees, Rbf, TxOutputSummary};
use fedimint_wallet_server::WalletInit;
use futures::stream::StreamExt;
use secp256k1::rand::rngs::OsRng;
use tokio::select;
use tracing::{info, warn};

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);
    let wallet_client = WalletClientInit::new(fixtures.client_esplora_rpc());
    fixtures.with_module(wallet_client, WalletInit)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

const PEG_IN_AMOUNT_SATS: u64 = 10000;
const PEG_OUT_AMOUNT_SATS: u64 = 1000;

async fn peg_in<'a>(
    client: &'a ClientHandleArc,
    bitcoin: &dyn BitcoinTest,
    finality_delay: u64,
    fed: &FederationTest,
) -> anyhow::Result<(BoxStream<'a, Amount>, bitcoin::Transaction)> {
    let mut balance_sub = client.subscribe_balance_changes(AmountUnit::BITCOIN).await;
    let initial_balance = balance_sub.ok().await?;

    await_consensus_upgrade(client, fed).await?;

    let wallet_module = &client.get_first_module::<WalletClientModule>()?;
    let (op, address, _) = wallet_module
        .allocate_deposit_address_expert_only(())
        .await?;
    info!(?address, "Peg-in address generated");
    let (_proof, tx) = bitcoin
        .send_and_mine_block(
            &address,
            bsats(PEG_IN_AMOUNT_SATS)
                + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000),
        )
        .await;
    let height = bitcoin
        .get_tx_block_height(&tx.compute_txid())
        .await
        .context("expected tx to be mined")?;
    info!(?height, ?tx, "Peg-in transaction mined");

    bitcoin.mine_blocks(finality_delay).await;

    wallet_module
        .await_num_deposits_by_operation_id(op, 1)
        .await?;
    assert_eq!(
        client.get_balance_for_btc().await?,
        initial_balance + sats(PEG_IN_AMOUNT_SATS)
    );
    assert_eq!(
        balance_sub.ok().await?,
        initial_balance + sats(PEG_IN_AMOUNT_SATS)
    );
    info!(?height, ?tx, "Peg-in transaction claimed");

    Ok((balance_sub, tx))
}

async fn await_consensus_to_catch_up(
    client: &ClientHandleArc,
    block_count: u64,
) -> anyhow::Result<u64> {
    let wallet = client.get_first_module::<WalletClientModule>()?;
    loop {
        let current_consensus = client
            .api()
            .with_module(wallet.id)
            .fetch_consensus_block_count()
            .await?;
        if current_consensus < block_count {
            info!(
                "Current consensus block count is {current_consensus}, waiting for consensus to reach block count {block_count}"
            );
            sleep_in_test(format!("Current consensus block count is {current_consensus}, waiting for consensus to reach block count {block_count}"), Duration::from_millis(100)).await;
        } else {
            info!("Current consensus block count is {current_consensus}, consensus caught up");
            return Ok(current_consensus);
        }
    }
}

async fn activate_manual_voting_for_online_peers(
    client: &ClientHandleArc,
    fed: &FederationTest,
) -> anyhow::Result<()> {
    let wallet_module_client_id = client.get_first_module::<WalletClientModule>()?.id;
    let activation_futures = fed.online_peer_ids().map(|peer_id| async move {
        info!("activating consensus version voting for peer {peer_id}");

        fed.new_admin_api(peer_id)
            .await?
            .with_module(wallet_module_client_id)
            .activate_consensus_version_voting(API_AUTH.clone())
            .await
            .map_err(|e| anyhow!("{e:?}"))
    });

    futures::future::try_join_all(activation_futures).await?;

    Ok(())
}

async fn await_consensus_upgrade(
    client: &ClientHandleArc,
    fed: &FederationTest,
) -> anyhow::Result<()> {
    // we need all peers to be online for automatic consensus version voting, so we
    // activate manual voting if the federation is degraded
    if fed.is_degraded() {
        activate_manual_voting_for_online_peers(client, fed).await?;
    }

    retry(
        "waiting for consensus upgrade",
        fedimint_core::util::backoff_util::aggressive_backoff(),
        || async {
            let is_upgraded = client
                .get_first_module::<WalletClientModule>()?
                .btc_tx_has_no_size_limit()
                .await?;

            anyhow::ensure!(is_upgraded);
            Ok(())
        },
    )
    .await
    .expect("Consensus upgrade didn't happen in time");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity_check_bitcoin_blocks() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // Avoid other tests from interfering here
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.server_bitcoin_rpc();
    info!("Starting test sanity_check_bitcoin_blocks");

    let finality_delay = 10; // TODO: get from config
    let initial_block_count = dyn_bitcoin_rpc.get_block_count().await?;
    info!("Initial block count is {initial_block_count}");
    bitcoin.mine_blocks(finality_delay).await;
    let mut current_block_count = dyn_bitcoin_rpc.get_block_count().await?;
    info!("Current block count after finality delay: {current_block_count}");
    assert!(current_block_count >= finality_delay);
    let current_consensus_block_count =
        await_consensus_to_catch_up(&client, current_block_count - finality_delay).await?;
    info!("Current consensus block count is {current_consensus_block_count}");
    let address = bitcoin.get_new_address().await;
    let (proof, tx) = bitcoin.send_and_mine_block(&address, bsats(1000)).await;
    current_block_count += 1; // we mined one block above
    assert_eq!(
        dyn_bitcoin_rpc.get_block_count().await?,
        current_block_count,
    );
    let expected_transaction_block_count = current_block_count;
    let expected_transaction_height = expected_transaction_block_count - 1;
    assert_eq!(
        bitcoin.get_tx_block_height(&tx.compute_txid()).await,
        Some(expected_transaction_height),
    );
    let expected_transaction_block_hash = dyn_bitcoin_rpc
        .get_block_hash(expected_transaction_height)
        .await?;
    assert_eq!(proof.block(), expected_transaction_block_hash);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn on_chain_peg_in_and_peg_out_happy_case() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test on_chain_peg_in_and_peg_out_happy_case");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;
    await_consensus_upgrade(&client, &fed).await?;

    assert_eq!(client.get_balance_for_btc().await?, sats(0));
    let (op, address, _) = wallet_module
        .allocate_deposit_address_expert_only(())
        .await?;

    // Test operation is created
    let operations = client
        .operation_log()
        .paginate_operations_rev(10, None)
        .await;
    assert_eq!(operations.len(), 1, "Expecting only the peg-in operation");

    let deposit_operation_id = operations[0].0.operation_id;
    let deposit_operation = &operations[0].1;
    assert_eq!(
        deposit_operation_id, op,
        "Operation ID should match the one returned by allocate_deposit_address"
    );

    assert_eq!(
        deposit_operation.operation_module_kind(),
        "wallet",
        "Peg-in operation should ke of kind wallet"
    );
    assert!(
        deposit_operation
            .meta::<serde_json::Value>()
            .get("variant")
            .and_then(|v| v.get("deposit"))
            .and_then(|d| d.get("address"))
            .is_some(),
        "Peg-in operation meta data should contain address"
    );

    // Test update stream returns expected updates
    let mut deposit_updates = wallet_module
        .subscribe_deposit(deposit_operation_id)
        .await?
        .into_stream();
    assert_eq!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::WaitingForTransaction
    );

    info!(?address, "Peg-in address generated");
    let (_proof, tx) = bitcoin
        .send_and_mine_block(
            &address,
            bsats(PEG_IN_AMOUNT_SATS)
                + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000),
        )
        .await;

    info!("Waiting for confirmation");
    assert_matches!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::WaitingForConfirmation { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    bitcoin.mine_blocks(finality_delay).await;

    // Afaik technically not necessary, but useful to speed up test (should probably
    // just poll more often in tests?)
    let await_update_while_rechecking = async {
        loop {
            wallet_module
                .recheck_pegin_address_by_op_id(op)
                .await
                .expect("Operation exists");
            select! {
                update = deposit_updates.next() => {
                    break update;
                },
                _ = sleep_in_test("Waiting for address recheck", Duration::from_millis(100)) => { }
            }
        }
    };

    info!("Waiting for claim tx");
    assert_matches!(
        await_update_while_rechecking.await.unwrap(),
        DepositStateV2::Confirmed { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    info!("Waiting for e-cash");
    assert_matches!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::Claimed { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    info!("Checking balance after deposit");
    let mut balance_sub = client.subscribe_balance_changes(AmountUnit::BITCOIN).await;
    assert_eq!(
        client.get_balance_for_btc().await?,
        sats(PEG_IN_AMOUNT_SATS)
    );
    assert_eq!(balance_sub.ok().await?, sats(PEG_IN_AMOUNT_SATS));

    assert_eq!(deposit_updates.next().await, None);

    info!("Peg-in finished for test on_chain_peg_in_and_peg_out_happy_case");
    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let fees = wallet_module.get_withdraw_fees(&address, peg_out).await?;
    assert_eq!(
        fees.total_weight, 871,
        "stateless wallet should have constructed a tx with a total weight=871"
    );
    let op = wallet_module.withdraw(&address, peg_out, fees, ()).await?;

    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees.amount().to_sat());
    assert_eq!(client.get_balance_for_btc().await?, balance_after_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_peg_out);

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };

    let expected_tx_fee = {
        let witness_scale_factor = 4;
        let sats_per_vbyte = fees.fee_rate.sats_per_kvb / 1000;
        let tx_vbytes = fees.total_weight.div_ceil(witness_scale_factor);
        Amount::from_sats(sats_per_vbyte * tx_vbytes)
    };
    let tx_fee = bitcoin.get_mempool_tx_fee(&txid).await;
    assert_eq!(tx_fee, expected_tx_fee);

    let received = bitcoin.mine_block_and_get_received(&address).await;
    assert_eq!(received, peg_out.into());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn on_chain_peg_in_detects_multiple() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test on_chain_peg_in_and_peg_out_happy_case");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let starting_balance = client.get_balance_for_btc().await?;
    info!(?starting_balance, "Starting balance");

    await_consensus_upgrade(&client, &fed).await?;

    let wallet_module = &client.get_first_module::<WalletClientModule>()?;
    let (op, address, tweak_idx) = wallet_module
        .allocate_deposit_address_expert_only(())
        .await?;

    // First peg-in
    {
        info!("Funding first peg-in transaction mined");
        let (_proof, tx) = bitcoin
            .send_and_mine_block(
                &address,
                bsats(PEG_IN_AMOUNT_SATS)
                    + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000),
            )
            .await;
        let height = bitcoin
            .get_tx_block_height(&tx.compute_txid())
            .await
            .context("expected tx to be mined")?;
        info!(?height, ?tx, txid = ?tx.compute_txid(), "First peg-in transaction mined");
        bitcoin.mine_blocks(finality_delay).await;
        wallet_module
            .await_num_deposits_by_operation_id(op, 1)
            .await?;
        assert_eq!(
            client.get_balance_for_btc().await?,
            sats(PEG_IN_AMOUNT_SATS) + starting_balance
        );
        info!(?height, ?tx, "First peg-in transaction claimed");
    }

    // Second peg-in
    {
        info!("Funding second peg-in transaction mined");
        let (_proof, tx) = bitcoin
            .send_and_mine_block(
                &address,
                bsats(PEG_IN_AMOUNT_SATS)
                    + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000),
            )
            .await;

        let height = bitcoin
            .get_tx_block_height(&tx.compute_txid())
            .await
            .context("expected tx to be mined")?;
        info!(?height, ?tx, txid = ?tx.compute_txid(), "Second peg-in transaction mined");
        bitcoin.mine_blocks(finality_delay).await;
        wallet_module.await_num_deposits(tweak_idx, 2).await?;
        assert_eq!(
            client.get_balance_for_btc().await?,
            sats(PEG_IN_AMOUNT_SATS * 2) + starting_balance
        );
        info!(?height, ?tx, "Second peg-in transaction claimed");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_out_fail_refund() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test peg_out_fail_refund");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let (mut balance_sub, _) = peg_in(&client, bitcoin.as_ref(), finality_delay, &fed).await?;

    info!("Peg-in finished for test peg_out_fail_refund");
    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);

    // Set invalid fees
    let fees = PegOutFees {
        fee_rate: Feerate { sats_per_kvb: 0 },
        total_weight: 0,
    };

    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    let op = wallet_module.withdraw(&address, peg_out, fees, ()).await?;
    assert_eq!(
        balance_sub.next().await.unwrap(),
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS)
    );

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    assert_matches!(sub.ok().await?, WithdrawState::Failed(_));

    // Check that we get our money back if the peg-out fails
    assert_eq!(balance_sub.next().await.unwrap(), sats(PEG_IN_AMOUNT_SATS));
    assert_eq!(
        client.get_balance_for_btc().await?,
        sats(PEG_IN_AMOUNT_SATS)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rbf_withdrawals_are_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // Need lock to keep tx in mempool from getting mined
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test rbf_withdrawals_are_rejected");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let (mut balance_sub, _) = peg_in(&client, bitcoin.as_ref(), finality_delay, &fed).await?;

    info!("Peg-in finished for test rbf_withdrawals_are_rejected");
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    let fees = wallet_module.get_withdraw_fees(&address, peg_out).await?;
    let op = wallet_module.withdraw(&address, peg_out, fees, ()).await?;

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let state = sub.ok().await?;
    let WithdrawState::Succeeded(txid) = state else {
        bail!("Unexpected state: {state:?}")
    };
    assert_eq!(
        bitcoin.get_mempool_tx_fee(&txid).await,
        fees.amount().into()
    );
    let balance_after_normal_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees.amount().to_sat());
    assert_eq!(
        client.get_balance_for_btc().await?,
        balance_after_normal_peg_out
    );
    assert_eq!(balance_sub.ok().await?, balance_after_normal_peg_out);

    // RBF by increasing sats per kvb by 1000
    let rbf = Rbf {
        fees: PegOutFees::new(1000, fees.total_weight),
        txid,
    };

    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    #[allow(deprecated)]
    let rbf_op = wallet_module.rbf_withdraw(rbf.clone(), ()).await?;
    let rbf_sub = wallet_module.subscribe_withdraw_updates(rbf_op).await?;
    let mut rbf_sub = rbf_sub.into_stream();

    assert_eq!(rbf_sub.ok().await?, WithdrawState::Created);
    match rbf_sub.ok().await? {
        WithdrawState::Failed(err) => {
            assert!(err.contains("The wallet output version is not supported by this federation"))
        }
        other => panic!("Unexpected state: {other:?}"),
    }

    assert_eq!(
        bitcoin.mine_block_and_get_received(&address).await,
        sats(PEG_OUT_AMOUNT_SATS)
    );

    // to prevent flakiness, we need to retry this check
    // see: https://github.com/fedimint/fedimint/issues/6190
    fedimint_core::util::retry(
        "verify client balance",
        fedimint_core::util::backoff_util::custom_backoff(
            Duration::from_millis(100),
            Duration::from_millis(100),
            Some(100),
        ),
        || async {
            let current_balance = client.get_balance_for_btc().await?;
            if current_balance == balance_after_normal_peg_out {
                Ok(())
            } else {
                let msg = format!(
                    "Balance is {current_balance}, expected {balance_after_normal_peg_out}"
                );
                warn!(msg);
                Err(anyhow::anyhow!(msg))
            }
        },
    )
    .await
    .expect("couldn't verify balance within 10s");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_must_wait_for_available_utxos() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // This test has many assumptions about bitcoin L1 blocks
    // and FM epochs, so we just lock the node
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.server_bitcoin_rpc();
    info!("Starting test peg_outs_must_wait_for_available_utxos");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let (mut balance_sub, _) = peg_in(&client, bitcoin.as_ref(), finality_delay, &fed).await?;

    info!("Peg-in finished for test peg_outs_must_wait_for_available_utxos");
    let address = bitcoin.get_new_address().await;
    let peg_out1 = PEG_OUT_AMOUNT_SATS;
    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    let fees1 = wallet_module
        .get_withdraw_fees(&address, bsats(peg_out1))
        .await?;
    let op = wallet_module
        .withdraw(&address, bsats(peg_out1), fees1, ())
        .await?;
    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees1.amount().to_sat());
    assert_eq!(client.get_balance_for_btc().await?, balance_after_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_peg_out);

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };
    bitcoin.get_mempool_tx_fee(&txid).await;

    // Do another peg-out
    // Note: important to use a different address, otherwise txid
    // of the peg-out transaction might be the same.
    // See: https://github.com/fedimint/fedimint/issues/3604
    let address = bitcoin.get_new_address().await;
    let peg_out2 = PEG_OUT_AMOUNT_SATS;
    let fees2 = wallet_module
        .get_withdraw_fees(&address, bsats(peg_out2))
        .await;
    // Must fail because change UTXOs are still being confirmed
    assert!(fees2.is_err());

    let current_block = dyn_bitcoin_rpc.get_block_count().await?;
    bitcoin.mine_blocks(finality_delay + 1).await;
    await_consensus_to_catch_up(&client, current_block + 1).await?;
    // Now change UTXOs are available and we can peg-out again
    let fees2 = wallet_module
        .get_withdraw_fees(&address, bsats(peg_out2))
        .await?;
    let op = wallet_module
        .withdraw(&address, bsats(peg_out2), fees2, ())
        .await?;
    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };

    bitcoin.get_mempool_tx_fee(&txid).await;
    let balance_after_second_peg_out = sats(
        PEG_IN_AMOUNT_SATS
            - peg_out1
            - peg_out2
            - fees1.amount().to_sat()
            - fees2.amount().to_sat(),
    );
    assert_eq!(
        client.get_balance_for_btc().await?,
        balance_after_second_peg_out
    );
    assert_eq!(balance_sub.ok().await?, balance_after_second_peg_out);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_ins_that_are_unconfirmed_are_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let bitcoin = fixtures.bitcoin();
    let dyn_bitcoin_rpc = fixtures.server_bitcoin_rpc();
    let bitcoin_rpc_connection = fixtures.server_bitcoin_rpc();
    let db = MemDatabase::new().into_database();
    let task_group = fedimint_core::task::TaskGroup::new();
    info!("Starting test peg_ins_that_are_unconfirmed_are_rejected");

    let (wallet_server_cfg, _) = build_wallet_server_configs()?;

    let module_instance_id = 1;
    let root_secret =
        PlainRootSecretStrategy::to_root_secret(&PlainRootSecretStrategy::random(&mut OsRng));
    let secp = fedimint_core::secp256k1::Secp256k1::new();
    let tweak_key = root_secret.to_secp_key(&secp);
    let pk = tweak_key.public_key();
    let wallet_config: WalletConfig = wallet_server_cfg[0].to_typed()?;
    let peg_in_descriptor = wallet_config.consensus.peg_in_descriptor;
    let finality_delay = wallet_config.consensus.finality_delay;

    let peg_in_address = peg_in_descriptor
        .tweak(&pk, secp256k1::SECP256K1)
        .address(wallet_config.consensus.network.0)?;

    let mut wallet = fedimint_wallet_server::Wallet::new(
        wallet_server_cfg[0].to_typed()?,
        &db,
        &task_group,
        PeerId::from(0),
        // FIXME: use proper mock
        DynGlobalApi::new(
            ConnectorRegistry::build_from_testing_env()?.bind().await?,
            [(
                PeerId::from(0),
                SafeUrl::from_str("ws://dummy.xyz").unwrap(),
            )]
            .into(),
            None,
        )?
        .with_module(module_instance_id),
        ServerBitcoinRpcMonitor::new(
            bitcoin_rpc_connection.clone(),
            Duration::from_secs(1),
            &TaskGroup::new(),
        ),
    )
    .await?;

    let mut dbtx = db.begin_transaction().await;

    // Generate a minimum number of blocks before sending transactions
    bitcoin.mine_blocks(finality_delay.into()).await;

    let block_count = dyn_bitcoin_rpc.get_block_count().await? as u32;
    let consensus_block_count = block_count - finality_delay;
    sync_wallet_to_block(
        &mut dbtx
            .to_ref_with_prefix_module_id(module_instance_id)
            .0
            .into_nc(),
        &mut wallet,
        consensus_block_count,
    )
    .await?;

    // Send peg-in transaction
    let (proof, transaction) = bitcoin
        .send_and_mine_block(&peg_in_address, bsats(PEG_IN_AMOUNT_SATS))
        .await;
    let output_index = transaction
        .output
        .iter()
        .enumerate()
        .find_map(|(index, o)| {
            if o.script_pubkey == peg_in_address.script_pubkey() {
                Some(index)
            } else {
                None
            }
        })
        .context("expected to find peg-in output")?;
    let input = fedimint_wallet_common::WalletInput::new_v0(PegInProof::new(
        proof,
        transaction,
        output_index.try_into()?,
        pk,
    )?);

    match wallet
        .process_input(
            &mut dbtx
                .to_ref_with_prefix_module_id(module_instance_id)
                .0
                .into_nc(),
            &input,
            InPoint {
                txid: TransactionId::all_zeros(),
                in_idx: 0,
            },
        )
        .await
    {
        Ok(_) => bail!("Expected peg-in to fail"),
        Err(e) => {
            assert!(e.to_string().contains("Unknown block hash in peg-in proof"));
        }
    }

    // For this transaction to be confirmed, we need to mine at least finality_delay
    bitcoin
        .mine_blocks((wallet_config.consensus.finality_delay).into())
        .await;
    let block_count = dyn_bitcoin_rpc.get_block_count().await? as u32;
    let consensus_block_count = block_count - finality_delay;
    sync_wallet_to_block(
        &mut dbtx
            .to_ref_with_prefix_module_id(module_instance_id)
            .0
            .into_nc(),
        &mut wallet,
        consensus_block_count,
    )
    .await?;

    assert_matches!(
        wallet
            .process_input(
                &mut dbtx
                    .to_ref_with_prefix_module_id(module_instance_id)
                    .0
                    .into_nc(),
                &input,
                InPoint {
                    txid: TransactionId::all_zeros(),
                    in_idx: 0,
                },
            )
            .await,
        Ok(_)
    );
    dbtx.commit_tx().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dust_deposits_are_ignored() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test dust_deposits_are_ignored");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;
    await_consensus_upgrade(&client, &fed).await?;

    assert_eq!(client.get_balance_for_btc().await?, sats(0));
    let (op, address, _) = wallet_module
        .allocate_deposit_address_expert_only(())
        .await?;

    info!(?address, "Peg-in address generated");
    let (_proof, tx) = bitcoin
        .send_and_mine_block(
            &address,
            bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000 - 1),
        )
        .await;

    let mut deposit_updates = wallet_module.subscribe_deposit(op).await?.into_stream();
    info!("Waiting for transaction");
    assert_matches!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::WaitingForTransaction
    );
    info!("Waiting for confirmation");
    assert_matches!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::WaitingForConfirmation { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    bitcoin.mine_blocks(finality_delay).await;

    // Afaik technically not necessary, but useful to speed up test (should probably
    // just poll more often in tests?)
    let await_update_while_rechecking = async {
        loop {
            wallet_module
                .recheck_pegin_address_by_op_id(op)
                .await
                .expect("Operation exists");
            select! {
                update = deposit_updates.next() => {
                    break update;
                },
                _ = sleep_in_test("Waiting for address recheck", Duration::from_millis(100)) => { }
            }
        }
    };

    info!("Waiting for claim tx");
    assert_matches!(
        await_update_while_rechecking.await.unwrap(),
        DepositStateV2::Confirmed { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    info!("Waiting for e-cash");
    assert_matches!(
        deposit_updates.next().await.unwrap(),
        DepositStateV2::Claimed { btc_out_point, .. } if btc_out_point.txid == tx.compute_txid()
    );

    info!("Checking balance after deposit");
    assert_eq!(client.get_balance_for_btc().await?, Amount::ZERO);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn construct_wallet_summary() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    info!("Starting test construct_wallet_summary");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut expected_available_utxos: HashSet<TxOutputSummary> = HashSet::new();

    fn sum_utxos<'a>(utxos: impl Iterator<Item = &'a TxOutputSummary>) -> bitcoin::Amount {
        utxos.fold(bsats(0), |acc, utxo| utxo.amount + acc)
    }

    // generate 3 peg-ins, verifying wallet summary after each
    for _ in 0..3 {
        let (_, tx) = peg_in(&client, bitcoin.as_ref(), finality_delay, &fed).await?;
        let expected_peg_in_amount =
            PEG_IN_AMOUNT_SATS + (wallet_module.get_fee_consensus().peg_in_abs.msats / 1000);

        let expected_available_utxo = tx
            .output
            .iter()
            .enumerate()
            .find_map(|(idx, output)| {
                // bitcoin core randomizes the change output index so we can't assume the fed's
                // utxo is always index 0
                if output.value.to_sat() == expected_peg_in_amount {
                    Some(TxOutputSummary {
                        outpoint: bitcoin::OutPoint {
                            txid: tx.compute_txid(),
                            vout: idx as u32,
                        },
                        amount: output.value,
                    })
                } else {
                    None
                }
            })
            .expect("peg-in transaction must contain federation's UTXO");

        assert!(expected_available_utxos.insert(expected_available_utxo));

        let wallet_summary = wallet_module.get_wallet_summary().await?;
        assert_eq!(
            sum_utxos(expected_available_utxos.iter()),
            wallet_summary.total_spendable_balance()
        );
        assert_eq!(bsats(0), wallet_summary.total_pending_change_balance());
        assert_eq!(
            expected_available_utxos,
            wallet_summary
                .spendable_utxos
                .clone()
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert_eq!(wallet_summary.pending_peg_out_txos(), vec![]);
        assert_eq!(wallet_summary.pending_change_utxos(), vec![]);
    }

    // generate a peg-out, verifying the summary:
    //   - while the tx is pending in the mempool
    //   - after the tx is mined and finalized
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let fees = wallet_module.get_withdraw_fees(&address, peg_out).await?;
    let op = wallet_module.withdraw(&address, peg_out, fees, ()).await?;

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);

    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };

    let wallet_summary_before_mining = wallet_module.get_wallet_summary().await?;
    info!(?wallet_summary_before_mining);

    let mempool_tx = fedimint_core::util::retry(
        "get peg-out mempool tx",
        fedimint_core::util::backoff_util::custom_backoff(
            Duration::from_millis(100),
            Duration::from_millis(100),
            Some(100),
        ),
        || async {
            bitcoin
                .get_mempool_tx(&txid)
                .await
                .ok_or(anyhow::anyhow!("No mempool tx found"))
        },
    )
    .await
    .expect("couldn't fetch mempool tx within 10s");
    info!(?mempool_tx);

    for input in mempool_tx.input {
        // using `find` is clunky, however it's necessary since `getrawtransaction`
        // doesn't include an amount with inputs so we cannot manually construct a
        // TxOutputSummary
        let consumed_utxo = expected_available_utxos
            .iter()
            .find(|utxo| utxo.outpoint == input.previous_output)
            .expect("wallet should have consumed spendable UTXO")
            .to_owned();

        assert!(expected_available_utxos.remove(&consumed_utxo))
    }

    let expected_pending_peg_out_txo = TxOutputSummary {
        outpoint: bitcoin::OutPoint { txid, vout: 0 },
        amount: mempool_tx
            .output
            .first()
            .expect("peg-out tx includes withdrawal output")
            .value,
    };

    let expected_pending_change_utxo = TxOutputSummary {
        outpoint: bitcoin::OutPoint { txid, vout: 1 },
        amount: mempool_tx
            .output
            .last()
            .expect("peg-out tx includes change output")
            .value,
    };

    assert_eq!(
        sum_utxos(expected_available_utxos.iter()),
        wallet_summary_before_mining.total_spendable_balance()
    );

    assert_eq!(
        mempool_tx
            .output
            .last()
            .expect("peg-out tx includes change output")
            .value,
        wallet_summary_before_mining.total_pending_change_balance()
    );

    assert_eq!(
        wallet_summary_before_mining
            .spendable_utxos
            .clone()
            .into_iter()
            .collect::<HashSet<_>>(),
        expected_available_utxos
    );

    assert_eq!(
        wallet_summary_before_mining.pending_peg_out_txos(),
        vec![expected_pending_peg_out_txo]
    );

    assert_eq!(
        wallet_summary_before_mining.pending_change_utxos(),
        vec![expected_pending_change_utxo]
    );

    bitcoin.mine_blocks(finality_delay + 1).await;
    let block_count = bitcoin.get_block_count().await;
    await_consensus_to_catch_up(&client, block_count - finality_delay).await?;

    let wallet_summary_after_mining = wallet_module.get_wallet_summary().await?;
    info!(?wallet_summary_after_mining);

    assert!(expected_available_utxos.insert(expected_pending_change_utxo));

    assert_eq!(
        sum_utxos(expected_available_utxos.iter()),
        wallet_summary_after_mining.total_spendable_balance()
    );

    assert_eq!(
        bsats(0),
        wallet_summary_after_mining.total_pending_change_balance()
    );

    assert_eq!(
        wallet_summary_after_mining
            .spendable_utxos
            .clone()
            .into_iter()
            .collect::<HashSet<_>>(),
        expected_available_utxos
    );

    assert_eq!(wallet_summary_after_mining.pending_peg_out_txos(), vec![]);

    assert_eq!(wallet_summary_after_mining.pending_change_utxos(), vec![]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_auto_consensus_voting() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_not_degraded().await;
    let client = fed.new_client().await;
    await_consensus_upgrade(&client, &fed).await?;

    Ok(())
}

async fn sync_wallet_to_block(
    dbtx: &mut DatabaseTransaction<'_>,
    wallet: &mut fedimint_wallet_server::Wallet,
    block_count: u32,
) -> anyhow::Result<()> {
    for peer in 0..(MINTS / 2 + 1) {
        let consensus_item = fedimint_wallet_common::WalletConsensusItem::BlockCount(block_count);
        let peer_id = PeerId::from(peer as u16);
        wallet
            .process_consensus_item(dbtx, consensus_item, peer_id)
            .await?;
    }
    Ok(())
}

const MINTS: usize = 5;

// TODO: Something similar to this is needed in every module, maybe we can
// remove some code duplication
fn build_wallet_server_configs() -> anyhow::Result<(
    Vec<fedimint_core::config::ServerModuleConfig>,
    fedimint_core::config::ClientModuleConfig,
)> {
    let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
    let args = fedimint_server_core::ConfigGenModuleArgs {
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
    };
    let wallet_cfg =
        fedimint_server::core::ServerModuleInit::trusted_dealer_gen(&WalletInit, &peers, &args);
    let client_cfg = fedimint_core::config::ClientModuleConfig::from_typed(
        0,
        <WalletInit as fedimint_server::core::ServerModuleInit>::kind(),
        fedimint_core::module::ModuleConsensusVersion::new(0, 0),
        fedimint_server::core::ServerModuleInit::get_client_config(
            &WalletInit,
            &wallet_cfg[&PeerId::from(0)].consensus,
        )?,
    )?;
    Ok((wallet_cfg.into_values().collect(), client_cfg))
}

#[cfg(test)]
mod fedimint_migration_tests {
    use anyhow::ensure;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::{Input, Psbt};
    use bitcoin::{
        Amount, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
        secp256k1,
    };
    use fedimint_client::module_init::DynClientModuleInit;
    use fedimint_core::core::ModuleInstanceId;
    use fedimint_core::db::{
        Database, DatabaseVersion, DatabaseVersionKey, DatabaseVersionKeyV0,
        IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::module::ModuleConsensusVersion;
    use fedimint_core::{Feerate, OutPoint, PeerId, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_server::core::DynServerModuleInit;
    use fedimint_testing::db::{
        BYTE_20, BYTE_32, BYTE_33, snapshot_db_migrations, snapshot_db_migrations_client,
        validate_migrations_client, validate_migrations_server,
    };
    use fedimint_wallet_client::client_db::{self, NextPegInTweakIndexKey, TweakIdx};
    use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
    use fedimint_wallet_common::{
        PegOutFees, Rbf, SpendableUTXO, WalletCommonInit, WalletOutputOutcome,
    };
    use fedimint_wallet_server::db::{
        BlockCountVoteKey, BlockCountVotePrefix, BlockHashByHeightKey, BlockHashByHeightKeyPrefix,
        BlockHashByHeightValue, BlockHashKey, BlockHashKeyPrefix, ClaimedPegInOutpointKey,
        ClaimedPegInOutpointPrefixKey, ConsensusVersionVoteKey, ConsensusVersionVotePrefix,
        ConsensusVersionVotingActivationKey, ConsensusVersionVotingActivationPrefix, DbKeyPrefix,
        FeeRateVoteKey, FeeRateVotePrefix, PegOutBitcoinTransaction,
        PegOutBitcoinTransactionPrefix, PegOutNonceKey, PegOutTxSignatureCI,
        PegOutTxSignatureCIPrefix, PendingTransactionKey, PendingTransactionPrefixKey, UTXOKey,
        UTXOPrefixKey, UnsignedTransactionKey, UnsignedTransactionPrefixKey, UnspentTxOutKey,
        UnspentTxOutPrefix,
    };
    use fedimint_wallet_server::{PendingTransaction, UnsignedTransaction};
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use secp256k1::Message;
    use strum::IntoEnumIterator;
    use tracing::info;

    use crate::WalletInit;

    /// Legacy wallet module instance ID used in old federations.
    /// This constant is only used for migration testing of old database
    /// formats.
    const LEGACY_WALLET_MODULE_INSTANCE_ID: ModuleInstanceId = 2;

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&BlockHashKey(BlockHash::from_byte_array(BYTE_32)), &())
            .await;

        let utxo = UTXOKey(bitcoin::OutPoint {
            txid: Txid::from_byte_array(BYTE_32),
            vout: 0,
        });
        let spendable_utxo = SpendableUTXO {
            tweak: BYTE_33,
            amount: Amount::from_sat(10000),
        };

        dbtx.insert_new_entry(&utxo, &spendable_utxo).await;

        dbtx.insert_new_entry(&PegOutNonceKey, &1).await;

        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &1)
            .await;

        dbtx.insert_new_entry(
            &ConsensusVersionVoteKey(PeerId::from(0)),
            &ModuleConsensusVersion::new(2, 0),
        )
        .await;

        dbtx.insert_new_entry(
            &FeeRateVoteKey(PeerId::from(0)),
            &Feerate { sats_per_kvb: 10 },
        )
        .await;

        let unsigned_transaction_key = UnsignedTransactionKey(Txid::from_byte_array(BYTE_32));

        let selected_utxos: Vec<(UTXOKey, SpendableUTXO)> = vec![(utxo.clone(), spendable_utxo)];

        let destination = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_slice(&BYTE_20).unwrap());
        let output: Vec<TxOut> = vec![TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: destination.clone(),
        }];

        dbtx.insert_new_entry(&UnspentTxOutKey(utxo.0), &output[0])
            .await;

        dbtx.insert_new_entry(&ConsensusVersionVotingActivationKey, &())
            .await;

        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: utxo.0,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output,
        };

        let inputs = vec![Input {
            non_witness_utxo: None,
            witness_utxo: Some(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: destination.clone(),
            }),
            partial_sigs: Default::default(),
            sighash_type: None,
            redeem_script: None,
            witness_script: Some(destination.clone()),
            bip32_derivation: Default::default(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: Default::default(),
            sha256_preimages: Default::default(),
            hash160_preimages: Default::default(),
            hash256_preimages: Default::default(),
            proprietary: Default::default(),
            tap_key_sig: Default::default(),
            tap_script_sigs: Default::default(),
            tap_scripts: Default::default(),
            tap_key_origins: Default::default(),
            tap_internal_key: Default::default(),
            tap_merkle_root: Default::default(),
            unknown: Default::default(),
        }];

        let psbt = Psbt {
            unsigned_tx: tx.clone(),
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs,
            outputs: vec![Default::default()],
        };

        let unsigned_transaction = UnsignedTransaction {
            psbt,
            signatures: vec![],
            change: Amount::from_sat(0),
            fees: PegOutFees {
                fee_rate: Feerate { sats_per_kvb: 1000 },
                total_weight: 40000,
            },
            destination: destination.clone(),
            selected_utxos: selected_utxos.clone(),
            peg_out_amount: Amount::from_sat(10000),
            rbf: None,
        };

        dbtx.insert_new_entry(&unsigned_transaction_key, &unsigned_transaction)
            .await;

        let pending_transaction_key = PendingTransactionKey(Txid::from_byte_array(BYTE_32));

        let pending_tx = PendingTransaction {
            tx,
            tweak: BYTE_33,
            change: Amount::from_sat(0),
            destination,
            fees: PegOutFees {
                fee_rate: Feerate { sats_per_kvb: 1000 },
                total_weight: 40000,
            },
            selected_utxos: selected_utxos.clone(),
            peg_out_amount: Amount::from_sat(10000),
            rbf: Some(Rbf {
                fees: PegOutFees {
                    fee_rate: Feerate { sats_per_kvb: 1000 },
                    total_weight: 40000,
                },
                txid: Txid::from_byte_array(BYTE_32),
            }),
        };
        dbtx.insert_new_entry(&pending_transaction_key, &pending_tx)
            .await;

        let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let signature = secp.sign_ecdsa(&Message::from_digest_slice(&BYTE_32).unwrap(), &sk);
        dbtx.insert_new_entry(
            &PegOutTxSignatureCI(Txid::from_byte_array(BYTE_32)),
            &vec![signature],
        )
        .await;

        let peg_out_bitcoin_tx = PegOutBitcoinTransaction(OutPoint {
            txid: TransactionId::from_slice(&BYTE_32).unwrap(),
            out_idx: 0,
        });

        dbtx.insert_new_entry(
            &peg_out_bitcoin_tx,
            &WalletOutputOutcome::new_v0(Txid::from_slice(&BYTE_32).unwrap()),
        )
        .await;

        dbtx.commit_tx().await;
    }

    async fn create_client_db_with_v0_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        // Will be migrated to `DatabaseVersionKey` during `apply_migrations`
        dbtx.insert_new_entry(&DatabaseVersionKeyV0, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&NextPegInTweakIndexKey, &TweakIdx(2))
            .await;

        dbtx.commit_tx().await;
    }

    async fn create_server_db_with_v1_data(db: Database) {
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_new_entry(
            &DatabaseVersionKey(LEGACY_WALLET_MODULE_INSTANCE_ID),
            &DatabaseVersion(1),
        )
        .await;

        dbtx.insert_new_entry(&ClaimedPegInOutpointKey(bitcoin::OutPoint::null()), &())
            .await;

        dbtx.insert_new_entry(
            &BlockHashByHeightKey(13),
            &BlockHashByHeightValue(BlockHash::from_byte_array(BYTE_32)),
        )
        .await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, WalletCommonInit>("wallet-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db.clone()).await;
                create_server_db_with_v1_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynServerModuleInit::from(WalletInit);
        validate_migrations_server(module, "wallet-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::BlockHash => {
                        let blocks = dbtx
                            .find_by_prefix(&BlockHashKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_blocks = blocks.len();
                        ensure!(
                            num_blocks > 0,
                            "validate_migrations was not able to read any BlockHashes"
                        );
                        info!("Validated BlockHash");
                    }
                    DbKeyPrefix::BlockHashByHeight => {
                        let blocks = dbtx
                            .find_by_prefix(&BlockHashByHeightKeyPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_blocks = blocks.len();
                        ensure!(
                            num_blocks == 1,
                            "validate_migrations was not able to read any BlockHashByHeightes"
                        );
                        info!("Validated BlockHashByHeight");
                    }
                    DbKeyPrefix::PegOutBitcoinOutPoint => {
                        let outpoints = dbtx
                            .find_by_prefix(&PegOutBitcoinTransactionPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_outpoints = outpoints.len();
                        ensure!(
                            num_outpoints > 0,
                            "validate_migrations was not able to read any PegOutBitcoinTransactions"
                        );
                        info!("Validated PegOutBitcoinOutPoint");
                    }
                    DbKeyPrefix::PegOutTxSigCi => {
                        let sigs = dbtx
                            .find_by_prefix(&PegOutTxSignatureCIPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_sigs = sigs.len();
                        ensure!(
                            num_sigs > 0,
                            "validate_migrations was not able to read any PegOutTxSigCi"
                        );
                        info!("Validated PegOutTxSigCi");
                    }
                    DbKeyPrefix::PendingTransaction => {
                        let pending_txs = dbtx
                            .find_by_prefix(&PendingTransactionPrefixKey)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_txs = pending_txs.len();
                        ensure!(
                            num_txs > 0,
                            "validate_migrations was not able to read any PendingTransactions"
                        );
                        info!("Validated PendingTransaction");
                    }
                    DbKeyPrefix::PegOutNonce => {
                        ensure!(dbtx.get_value(&PegOutNonceKey).await.is_some());
                        info!("Validated PegOutNonce");
                    }
                    DbKeyPrefix::UnsignedTransaction => {
                        let unsigned_txs = dbtx
                            .find_by_prefix(&UnsignedTransactionPrefixKey)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_txs = unsigned_txs.len();
                        ensure!(
                            num_txs > 0,
                            "validate_migrations was not able to read any UnsignedTransactions"
                        );
                        info!("Validated UnsignedTransaction");
                    }
                    DbKeyPrefix::Utxo => {
                        let utxos = dbtx
                            .find_by_prefix(&UTXOPrefixKey)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_utxos = utxos.len();
                        ensure!(
                            num_utxos > 0,
                            "validate_migrations was not able to read any UTXOs"
                        );
                        info!("Validated Utxo");
                    }
                    DbKeyPrefix::BlockCountVote => {
                        let heights = dbtx
                            .find_by_prefix(&BlockCountVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_heights = heights.len();
                        ensure!(
                            num_heights > 0,
                            "validate_migrations was not able to read any block height votes"
                        );
                        info!("Validated BlockCountVote");
                    }
                    DbKeyPrefix::FeeRateVote => {
                        let rates = dbtx
                            .find_by_prefix(&FeeRateVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_rates = rates.len();
                        ensure!(
                            num_rates > 0,
                            "validate_migrations was not able to read any fee rate votes"
                        );
                        info!("Validated FeeRateVote");
                    }
                    DbKeyPrefix::ClaimedPegInOutpoint => {
                        let claimed_peg_ins = dbtx
                            .find_by_prefix(&ClaimedPegInOutpointPrefixKey)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_peg_ins = claimed_peg_ins.len();
                        ensure!(
                            num_peg_ins > 0,
                            "validate_migrations was not able to read any claimed peg-in outpoints"
                        );
                        info!("Validated PeggedInOutpoint");
                    }
                    DbKeyPrefix::ConsensusVersionVote => {
                        let votes = dbtx
                            .find_by_prefix(&ConsensusVersionVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_votes = votes.len();
                        ensure!(
                            num_votes > 0,
                            "validate_migrations was not able to read any consensus version votes"
                        );
                        info!("Validated ConsensusVersionVote");
                    }
                    DbKeyPrefix::UnspentTxOut => {
                        let utxos = dbtx
                            .find_by_prefix(&UnspentTxOutPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_utxos = utxos.len();
                        ensure!(
                            num_utxos > 0,
                            "validate_migrations was not able to read any utxos"
                        );
                        info!("Validated UnspendTxOut");
                    }
                    DbKeyPrefix::ConsensusVersionVotingActivation => {
                        let activations = dbtx
                            .find_by_prefix(&ConsensusVersionVotingActivationPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        let num_activations = activations.len();
                        ensure!(
                            num_activations > 0,
                            "validate_migrations was not able to read any version voting activation"
                        );
                        info!("Validated ConsensusVersionVotingActivation");
                    }
                    DbKeyPrefix::RecoveryItem => {
                        // Recovery items are new and won't be in old snapshots
                    }
                }
            }
            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_client_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations_client::<_, _, WalletCommonInit>(
            "wallet-client-v0",
            |db| Box::pin(async { create_client_db_with_v0_data(db).await }),
            || (Vec::new(), Vec::new()),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynClientModuleInit::from(WalletClientInit::default());
        validate_migrations_client::<_, _, WalletClientModule>(
            module,
            "wallet-client",
            |db, _, _| async move {
                let mut dbtx = db.begin_transaction_nc().await;
                for prefix in client_db::DbKeyPrefix::iter() {
                    match prefix {
                        client_db::DbKeyPrefix::NextPegInTweakIndex => {
                            let next_peg_in_tweak = dbtx.get_value(&NextPegInTweakIndexKey).await;
                            ensure!(
                                next_peg_in_tweak.is_some(),
                                "validate_migrations was not able to read any peg in tweak index"
                            );
                            info!("Validated next peg in tweak index");
                        }
                        client_db::DbKeyPrefix::PegInTweakIndex => {}
                        client_db::DbKeyPrefix::ClaimedPegIn => {}
                        client_db::DbKeyPrefix::RecoveryFinalized => {}
                        client_db::DbKeyPrefix::RecoveryState => {}
                        client_db::DbKeyPrefix::SupportsSafeDeposit => {}
                        client_db::DbKeyPrefix::ExternalReservedStart
                        | client_db::DbKeyPrefix::CoreInternalReservedStart
                        | client_db::DbKeyPrefix::CoreInternalReservedEnd => {}
                    }
                }

                Ok(())
            },
        )
        .await
    }
}

/// Tests that multiple deposits to the same address create separate operation log entries
#[tokio::test(flavor = "multi_thread")]
async fn multiple_deposits_create_separate_operations() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    info!("Starting test multiple_deposits_create_separate_operations");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;
    await_consensus_upgrade(&client, &fed).await?;

    let wallet_module = client.get_first_module::<WalletClientModule>()?;
    
    // Allocate a single deposit address
    let (address_op_id, address, _) = wallet_module
        .allocate_deposit_address_expert_only(())
        .await?;
    info!(?address, "Deposit address allocated");

    // Verify the initial address allocation operation exists
    let initial_ops = client.operation_log().paginate_operations_rev(100, None).await;
    let address_creation_op = initial_ops
        .iter()
        .find(|(_, entry)| entry.operation_id() == address_op_id);
    assert!(address_creation_op.is_some(), "Address creation operation should exist");

    // Send first deposit to the address
    let first_deposit_amount = bsats(PEG_IN_AMOUNT_SATS)
        + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000);
    let (_proof, tx1) = bitcoin
        .send_and_mine_block(&address, first_deposit_amount)
        .await;
    info!(?tx1, "First deposit transaction mined");

    // Wait for finality and claim
    bitcoin.mine_blocks(finality_delay).await;
    wallet_module.await_num_deposits_by_operation_id(address_op_id, 1).await?;
    info!("First deposit claimed");

    // Send second deposit to the same address
    let second_deposit_amount = bsats(PEG_IN_AMOUNT_SATS + 5000)
        + bsats(wallet_module.get_fee_consensus().peg_in_abs.msats / 1000);
    let (_proof, tx2) = bitcoin
        .send_and_mine_block(&address, second_deposit_amount)
        .await;
    info!(?tx2, "Second deposit transaction mined");

    // Wait for finality and claim
    bitcoin.mine_blocks(finality_delay).await;
    wallet_module.await_num_deposits_by_operation_id(address_op_id, 2).await?;
    info!("Second deposit claimed");

    // Verify the operation log structure
    let all_ops = client.operation_log().paginate_operations_rev(100, None).await;
    info!("Total operations in log: {}", all_ops.len());

    // Find all wallet operations
    let wallet_ops: Vec<_> = all_ops
        .iter()
        .filter(|(_, entry)| entry.operation_module_kind() == WalletCommonInit::KIND.as_str())
        .collect();

    // Should have: 1 address allocation + 2 deposit claims = 3 operations
    assert!(
        wallet_ops.len() >= 3,
        "Expected at least 3 wallet operations (1 address + 2 deposits), found {}",
        wallet_ops.len()
    );

    // Verify address allocation operation
    let address_ops: Vec<_> = wallet_ops
        .iter()
        .filter(|(_, entry)| {
            let meta: WalletOperationMeta = serde_json::from_value(entry.meta().clone())
                .expect("Failed to parse wallet operation meta");
            matches!(meta.variant, WalletOperationMetaVariant::Deposit { .. })
        })
        .collect();
    assert_eq!(
        address_ops.len(),
        1,
        "Expected exactly 1 address allocation operation, found {}",
        address_ops.len()
    );

    // Verify deposit claim operations
    let deposit_claim_ops: Vec<_> = wallet_ops
        .iter()
        .filter(|(_, entry)| {
            let meta: WalletOperationMeta = serde_json::from_value(entry.meta().clone())
                .expect("Failed to parse wallet operation meta");
            matches!(meta.variant, WalletOperationMetaVariant::ReceiveDeposit { .. })
        })
        .collect();

    assert_eq!(
        deposit_claim_ops.len(),
        2,
        "Expected exactly 2 ReceiveDeposit operations for the two deposits, found {}",
        deposit_claim_ops.len()
    );

    // Validate each deposit operation contains correct data
    let mut found_tx1 = false;
    let mut found_tx2 = false;

    for (_, entry) in deposit_claim_ops {
        let meta: WalletOperationMeta = serde_json::from_value(entry.meta().clone())
            .expect("Failed to parse wallet operation meta");
        
        if let WalletOperationMetaVariant::ReceiveDeposit {
            address_operation_id,
            btc_out_point,
            amount,
            claim_txid,
            tweak_idx,
            change,
        } = meta.variant
        {
            // Verify address_operation_id matches the parent address allocation operation
            assert_eq!(
                address_operation_id, address_op_id,
                "Deposit operation should reference the address allocation operation as parent"
            );

            // Verify each deposit has a unique outpoint
            if btc_out_point.txid == tx1.compute_txid() {
                found_tx1 = true;
                info!(
                    ?btc_out_point,
                    ?amount,
                    ?claim_txid,
                    ?tweak_idx,
                    change_len = change.len(),
                    ?address_operation_id,
                    "First deposit operation validated"
                );
            } else if btc_out_point.txid == tx2.compute_txid() {
                found_tx2 = true;
                info!(
                    ?btc_out_point,
                    ?amount,
                    ?claim_txid,
                    ?tweak_idx,
                    change_len = change.len(),
                    ?address_operation_id,
                    "Second deposit operation validated"
                );
            }

            // Verify operation has valid claim transaction ID
            assert_ne!(
                claim_txid,
                TransactionId::from_byte_array([0; 32]),
                "Claim transaction ID should be valid"
            );
        }
    }

    assert!(found_tx1, "Should find operation for first deposit transaction");
    assert!(found_tx2, "Should find operation for second deposit transaction");

    // Verify final balance reflects both deposits
    let expected_balance = sats(PEG_IN_AMOUNT_SATS + PEG_IN_AMOUNT_SATS + 5000);
    assert_eq!(
        client.get_balance_for_btc().await?,
        expected_balance,
        "Final balance should reflect both deposits"
    );

    info!("Operation log validation complete - all checks passed");
    Ok(())
}

// Verify the correct Bitcoin RPC is used

#[test]
fn verify_bitcoind_backend() {
    let fixtures = fixtures();
    let dyn_bitcoin_rpc = fixtures.server_bitcoin_rpc();
    let bitcoin_rpc_kind = dyn_bitcoin_rpc.get_bitcoin_rpc_config().kind;

    assert_eq!(
        bitcoin_rpc_kind,
        if env::var(FM_TEST_USE_REAL_DAEMONS_ENV) == Ok("1".to_string()) {
            env::var(FM_TEST_BACKEND_BITCOIN_RPC_KIND_ENV).unwrap_or_else(|_| "bitcoind".into())
        } else {
            "mock_kind".into()
        }
    )
}

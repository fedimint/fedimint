use std::time::{Duration, SystemTime};

use anyhow::{bail, Context};
use assert_matches::assert_matches;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{self, Secp256k1};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::ClientArc;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{DatabaseTransaction, IRawDatabaseExt};
use fedimint_core::task::sleep;
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{sats, Amount, Feerate, PeerId, ServerModule};
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyInit;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{DepositState, WalletClientInit, WalletClientModule, WithdrawState};
use fedimint_wallet_common::config::{WalletConfig, WalletGenParams};
use fedimint_wallet_common::tweakable::Tweakable;
use fedimint_wallet_common::txoproof::PegInProof;
use fedimint_wallet_common::{PegOutFees, Rbf};
use fedimint_wallet_server::WalletInit;
use futures::stream::StreamExt;
use tracing::info;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit, DummyGenParams::default());
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());
    let wallet_client = WalletClientInit::new(fixtures.bitcoin_client());
    fixtures.with_module(wallet_client, WalletInit, wallet_params)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

const PEG_IN_AMOUNT_SATS: u64 = 5000;
const PEG_OUT_AMOUNT_SATS: u64 = 1000;
const PEG_IN_TIMEOUT: Duration = Duration::from_secs(60);

async fn peg_in<'a>(
    client: &'a ClientArc,
    bitcoin: &dyn BitcoinTest,
    dyn_bitcoin_rpc: &DynBitcoindRpc,
    finality_delay: u64,
) -> anyhow::Result<BoxStream<'a, Amount>> {
    let valid_until = SystemTime::now() + PEG_IN_TIMEOUT;

    let mut balance_sub = client.subscribe_balance_changes().await;
    assert_eq!(balance_sub.ok().await?, sats(0));

    let wallet_module = &client.get_first_module::<WalletClientModule>();
    let (op, address) = wallet_module.get_deposit_address(valid_until, ()).await?;
    info!(?address, "Peg-in address generated");
    let (_proof, tx) = bitcoin
        .send_and_mine_block(&address, bsats(PEG_IN_AMOUNT_SATS))
        .await;
    let height = dyn_bitcoin_rpc
        .get_tx_block_height(&tx.txid())
        .await?
        .context("expected tx to be mined")?;
    info!(?height, ?tx, "Peg-in transaction mined");
    let sub = wallet_module.subscribe_deposit_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, DepositState::WaitingForTransaction);
    assert_matches!(sub.ok().await?, DepositState::WaitingForConfirmation { .. });

    bitcoin.mine_blocks(finality_delay).await;
    assert!(matches!(sub.ok().await?, DepositState::Confirmed(_)));
    assert!(matches!(sub.ok().await?, DepositState::Claimed(_)));
    assert_eq!(client.get_balance().await, sats(PEG_IN_AMOUNT_SATS));
    assert_eq!(balance_sub.ok().await?, sats(PEG_IN_AMOUNT_SATS));
    info!(?height, ?tx, "Peg-in transaction claimed");

    Ok(balance_sub)
}

async fn await_consensus_to_catch_up(client: &ClientArc, block_count: u64) -> anyhow::Result<u64> {
    let wallet = client.get_first_module::<WalletClientModule>();
    loop {
        let current_consensus = client
            .api()
            .with_module(wallet.id)
            .fetch_consensus_block_count()
            .await?;
        if current_consensus < block_count {
            info!("Current consensus block count is {current_consensus}, waiting for consensus to reach block count {block_count}");
            sleep(Duration::from_secs(1)).await;
        } else {
            info!("Current consensus block count is {current_consensus}, consensus caught up");
            return Ok(current_consensus);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sanity_check_bitcoin_blocks() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // Avoid other tests from interfering here
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
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
        dyn_bitcoin_rpc.get_tx_block_height(&tx.txid()).await?,
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
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    info!("Starting test on_chain_peg_in_and_peg_out_happy_case");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    info!("Peg-in finished for test on_chain_peg_in_and_peg_out_happy_case");
    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let wallet_module = client.get_first_module::<WalletClientModule>();
    let fees = wallet_module
        .get_withdraw_fees(address.clone(), peg_out)
        .await?;
    assert_eq!(
        fees.total_weight, 871,
        "stateless wallet should have constructed a tx with a total weight=871"
    );
    let op = wallet_module
        .withdraw(address.clone(), peg_out, fees, ())
        .await?;

    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees.amount().to_sat());
    assert_eq!(client.get_balance().await, balance_after_peg_out);
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
        let tx_vbytes = (fees.total_weight + witness_scale_factor - 1) / witness_scale_factor;
        Amount::from_sats(sats_per_vbyte * tx_vbytes)
    };
    let tx_fee = bitcoin.get_mempool_tx_fee(&txid).await;
    assert_eq!(tx_fee, expected_tx_fee);

    let received = bitcoin.mine_block_and_get_received(&address).await;
    assert_eq!(received, peg_out.into());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_out_fail_refund() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    info!("Starting test peg_out_fail_refund");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    info!("Peg-in finished for test peg_out_fail_refund");
    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);

    // Set invalid fees
    let fees = PegOutFees {
        fee_rate: Feerate { sats_per_kvb: 0 },
        total_weight: 0,
    };

    let wallet_module = client.get_first_module::<WalletClientModule>();
    let op = wallet_module
        .withdraw(address.clone(), peg_out, fees, ())
        .await?;
    assert_eq!(
        balance_sub.next().await.unwrap(),
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS)
    );

    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    assert!(matches!(sub.ok().await?, WithdrawState::Failed(_)));

    // Check that we get our money back if the peg-out fails
    assert_eq!(balance_sub.next().await.unwrap(), sats(PEG_IN_AMOUNT_SATS));
    assert_eq!(client.get_balance().await, sats(PEG_IN_AMOUNT_SATS));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_support_rbf() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // Need lock to keep tx in mempool from getting mined
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    info!("Starting test peg_outs_support_rbf");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    info!("Peg-in finished for test peg_outs_support_rbf");
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let wallet_module = client.get_first_module::<WalletClientModule>();
    let fees = wallet_module
        .get_withdraw_fees(address.clone(), peg_out)
        .await?;
    let op = wallet_module
        .withdraw(address.clone(), peg_out, fees, ())
        .await?;

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
    assert_eq!(client.get_balance().await, balance_after_normal_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_normal_peg_out);

    // RBF by increasing sats per kvb by 1000
    let rbf = Rbf {
        fees: PegOutFees::new(1000, fees.total_weight),
        txid,
    };
    let wallet_module = client.get_first_module::<WalletClientModule>();
    let op = wallet_module.rbf_withdraw(rbf.clone(), ()).await?;
    let sub = wallet_module.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };
    let total_fees = fees.amount() + rbf.fees.amount();
    assert_eq!(bitcoin.get_mempool_tx_fee(&txid).await, total_fees.into());
    assert_eq!(
        bitcoin.mine_block_and_get_received(&address).await,
        sats(PEG_OUT_AMOUNT_SATS)
    );
    let balance_after_rbf_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - total_fees.to_sat());
    let current_balance = client.get_balance().await;
    assert_eq!(balance_sub.ok().await?, current_balance);
    // So we don't know which transaction will get mined first, it could be
    // any one of the two, so we accept both
    if current_balance != balance_after_rbf_peg_out
        && current_balance != balance_after_normal_peg_out
    {
        bail!(
            "Balance is {current_balance}, expected {balance_after_rbf_peg_out} or {balance_after_normal_peg_out}"
        )
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_outs_must_wait_for_available_utxos() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed().await;
    let client = fed.new_client().await;
    let bitcoin = fixtures.bitcoin();
    // This test has many assumptions about bitcoin L1 blocks
    // and FM epochs, so we just lock the node
    let bitcoin = bitcoin.lock_exclusive().await;
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    info!("Starting test peg_outs_must_wait_for_available_utxos");

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    info!("Peg-in finished for test peg_outs_must_wait_for_available_utxos");
    let address = bitcoin.get_new_address().await;
    let peg_out1 = PEG_OUT_AMOUNT_SATS;
    let wallet_module = client.get_first_module::<WalletClientModule>();
    let fees1 = wallet_module
        .get_withdraw_fees(address.clone(), bsats(peg_out1))
        .await?;
    let op = wallet_module
        .withdraw(address.clone(), bsats(peg_out1), fees1, ())
        .await?;
    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees1.amount().to_sat());
    assert_eq!(client.get_balance().await, balance_after_peg_out);
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
        .get_withdraw_fees(address.clone(), bsats(peg_out2))
        .await;
    // Must fail because change UTXOs are still being confirmed
    assert!(fees2.is_err());

    let current_block = dyn_bitcoin_rpc.get_block_count().await?;
    bitcoin.mine_blocks(finality_delay + 1).await;
    await_consensus_to_catch_up(&client, current_block + 1).await?;
    // Now change UTXOs are available and we can peg-out again
    let fees2 = wallet_module
        .get_withdraw_fees(address.clone(), bsats(peg_out2))
        .await?;
    let op = wallet_module
        .withdraw(address.clone(), bsats(peg_out2), fees2, ())
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
    assert_eq!(client.get_balance().await, balance_after_second_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_second_peg_out);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peg_ins_that_are_unconfirmed_are_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let bitcoin = fixtures.bitcoin();
    let server_bitcoin_rpc_config = fixtures.bitcoin_server();
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    let db = MemDatabase::new().into_database();
    let mut task_group = fedimint_core::task::TaskGroup::new();
    info!("Starting test peg_ins_that_are_unconfirmed_are_rejected");

    let (wallet_server_cfg, _) = build_wallet_server_configs(server_bitcoin_rpc_config)?;

    let module_instance_id = 1;
    let root_secret =
        PlainRootSecretStrategy::to_root_secret(&PlainRootSecretStrategy::random(&mut OsRng));
    let secp = Secp256k1::new();
    let tweak_key = root_secret.to_secp_key(&secp);
    let pk = tweak_key.public_key();
    let wallet_config: WalletConfig = wallet_server_cfg[0].to_typed()?;
    let peg_in_descriptor = wallet_config.consensus.peg_in_descriptor;

    let peg_in_address = peg_in_descriptor
        .tweak(&pk, secp256k1::SECP256K1)
        .address(wallet_config.consensus.network)?;

    let mut wallet = fedimint_wallet_server::Wallet::new_with_bitcoind(
        wallet_server_cfg[0].to_typed()?,
        db.clone(),
        dyn_bitcoin_rpc.clone(),
        &mut task_group,
        PeerId::from(0),
    )
    .await?;

    let mut dbtx = db.begin_transaction().await;

    // Generate a minimum number of blocks before sending transactions
    bitcoin
        .mine_blocks(wallet_config.consensus.finality_delay.into())
        .await;

    let block_count = dyn_bitcoin_rpc.get_block_count().await?;
    sync_wallet_to_block(
        &mut dbtx
            .to_ref_with_prefix_module_id(module_instance_id)
            .into_nc(),
        &mut wallet,
        block_count.try_into()?,
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
                .into_nc(),
            &input,
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
    let block_count = dyn_bitcoin_rpc.get_block_count().await?;
    sync_wallet_to_block(
        &mut dbtx
            .to_ref_with_prefix_module_id(module_instance_id)
            .into_nc(),
        &mut wallet,
        block_count.try_into()?,
    )
    .await?;

    assert_matches!(
        wallet
            .process_input(
                &mut dbtx
                    .to_ref_with_prefix_module_id(module_instance_id)
                    .into_nc(),
                &input,
            )
            .await,
        Ok(_)
    );
    dbtx.commit_tx().await;
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
fn build_wallet_server_configs(
    bitcoin_rpc: BitcoinRpcConfig,
) -> anyhow::Result<(
    Vec<fedimint_core::config::ServerModuleConfig>,
    fedimint_core::config::ClientModuleConfig,
)> {
    let peers = (0..MINTS as u16).map(PeerId::from).collect::<Vec<_>>();
    let wallet_cfg = fedimint_core::module::ServerModuleInit::trusted_dealer_gen(
        &WalletInit,
        &peers,
        &fedimint_core::config::ConfigGenModuleParams::from_typed(WalletGenParams {
            local: fedimint_wallet_common::config::WalletGenParamsLocal {
                bitcoin_rpc: bitcoin_rpc.clone(),
            },
            consensus: fedimint_wallet_common::config::WalletGenParamsConsensus {
                network: bitcoin::Network::Regtest,
                finality_delay: 10,
                client_default_bitcoin_rpc: bitcoin_rpc.clone(),
            },
        })?,
    );
    let client_cfg = fedimint_core::config::ClientModuleConfig::from_typed(
        0,
        <WalletInit as fedimint_core::module::ServerModuleInit>::kind(),
        fedimint_core::module::ModuleConsensusVersion::new(0, 0),
        fedimint_core::module::ServerModuleInit::get_client_config(
            &WalletInit,
            &wallet_cfg[&PeerId::from(0)].consensus,
        )?,
    )?;
    Ok((wallet_cfg.into_values().collect(), client_cfg))
}

#[cfg(test)]
mod fedimint_migration_tests {
    use anyhow::{ensure, Context};
    use bitcoin::psbt::{Input, PartiallySignedTransaction};
    use bitcoin::{
        Amount, BlockHash, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid,
        WPubkeyHash,
    };
    use fedimint_client::module::init::DynClientModuleInit;
    use fedimint_client::module::ClientModule;
    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
    use fedimint_core::db::{
        apply_migrations, DatabaseTransaction, DatabaseVersion, DatabaseVersionKey,
        IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::{CommonModuleInit, DynServerModuleInit};
    use fedimint_core::{BitcoinHash, Feerate, OutPoint, PeerId, ServerModule, TransactionId};
    use fedimint_logging::TracingSetup;
    use fedimint_testing::db::{
        prepare_db_migration_snapshot, validate_migrations, BYTE_20, BYTE_32, BYTE_33,
    };
    use fedimint_wallet_client::client_db::NextPegInTweakIndexKey;
    use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
    use fedimint_wallet_common::db::{
        BlockCountVoteKey, BlockCountVotePrefix, BlockHashKey, BlockHashKeyPrefix, DbKeyPrefix,
        FeeRateVoteKey, FeeRateVotePrefix, PegOutBitcoinTransaction,
        PegOutBitcoinTransactionPrefix, PegOutNonceKey, PegOutTxSignatureCI,
        PegOutTxSignatureCIPrefix, PendingTransactionKey, PendingTransactionPrefixKey, UTXOKey,
        UTXOPrefixKey, UnsignedTransactionKey, UnsignedTransactionPrefixKey,
    };
    use fedimint_wallet_common::{
        PegOutFees, PendingTransaction, Rbf, SpendableUTXO, UnsignedTransaction, WalletCommonInit,
        WalletOutputOutcome,
    };
    use fedimint_wallet_server::Wallet;
    use futures::StreamExt;
    use rand::rngs::OsRng;
    use secp256k1::Message;
    use strum::IntoEnumIterator;
    use tracing::info;

    use crate::WalletInit;

    /// Create a database with version 0 data. The database produced is not
    /// intended to be real data or semantically correct. It is only
    /// intended to provide coverage when reading the database
    /// in future code versions. This function should not be updated when
    /// database keys/values change - instead a new function should be added
    /// that creates a new database backup that can be tested.
    async fn create_server_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&BlockHashKey(BlockHash::from_slice(&BYTE_32).unwrap()), &())
            .await;

        let utxo = UTXOKey(bitcoin::OutPoint {
            txid: Txid::from_slice(&BYTE_32).unwrap(),
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
            &FeeRateVoteKey(PeerId::from(0)),
            &Feerate { sats_per_kvb: 10 },
        )
        .await;

        let unsigned_transaction_key = UnsignedTransactionKey(Txid::from_slice(&BYTE_32).unwrap());

        let selected_utxos: Vec<(UTXOKey, SpendableUTXO)> = vec![(utxo.clone(), spendable_utxo)];

        let destination = Script::new_v0_p2wpkh(&WPubkeyHash::from_slice(&BYTE_20).unwrap());
        let output: Vec<TxOut> = vec![TxOut {
            value: 10000,
            script_pubkey: destination.clone(),
        }];

        let transaction = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
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
            witness_utxo: Some(TxOut {
                value: 10000,
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

        let psbt = PartiallySignedTransaction {
            unsigned_tx: transaction.clone(),
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

        let pending_transaction_key = PendingTransactionKey(Txid::from_slice(&BYTE_32).unwrap());

        let pending_tx = PendingTransaction {
            tx: transaction,
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
                txid: Txid::from_slice(&BYTE_32).unwrap(),
            }),
        };
        dbtx.insert_new_entry(&pending_transaction_key, &pending_tx)
            .await;

        let (sk, _) = secp256k1::generate_keypair(&mut OsRng);
        let secp = secp256k1::Secp256k1::new();
        let signature = secp.sign_ecdsa(&Message::from_slice(&BYTE_32).unwrap(), &sk);
        dbtx.insert_new_entry(
            &PegOutTxSignatureCI(Txid::from_slice(&BYTE_32).unwrap()),
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
    }

    async fn create_client_db_with_v0_data(mut dbtx: DatabaseTransaction<'_>) {
        dbtx.insert_new_entry(&DatabaseVersionKey, &DatabaseVersion(0))
            .await;

        dbtx.insert_new_entry(&NextPegInTweakIndexKey, &2).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_server_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "wallet-server-v0",
            |dbtx| {
                Box::pin(async move {
                    create_server_db_with_v0_data(dbtx).await;
                })
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_WALLET,
                WalletCommonInit::KIND,
                <Wallet as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        validate_migrations(
            "wallet-server",
            |db| async move {
                let module = DynServerModuleInit::from(WalletInit);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .context("Error applying migrations to temp database")?;

                // Verify that all of the data from the wallet namespace can be read. If a
                // database migration failed or was not properly supplied,
                // the struct will fail to be read.
                let mut dbtx = db.begin_transaction().await;

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
                        }
                        DbKeyPrefix::PegOutNonce => {
                            ensure!(dbtx
                                .get_value(&PegOutNonceKey)
                                .await
                                .is_some());
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
                        }
                    }
                }
                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_WALLET,
                WalletCommonInit::KIND,
                <Wallet as ServerModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_client_db_migration_snapshots() -> anyhow::Result<()> {
        prepare_db_migration_snapshot(
            "wallet-client-v0",
            |dbtx| Box::pin(async move { create_client_db_with_v0_data(dbtx).await }),
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_WALLET,
                WalletCommonInit::KIND,
                <WalletClientModule as ClientModule>::decoder(),
            )]),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_migrations() -> anyhow::Result<()> {
        TracingSetup::default().init()?;

        validate_migrations(
            "wallet-client",
            |db| async move {
                let module = DynClientModuleInit::from(WalletClientInit::default());
                apply_migrations(
                    &db,
                    WalletCommonInit::KIND.to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .context("Error applying migrations to client database")?;

                let mut dbtx = db.begin_transaction().await;

                for prefix in fedimint_wallet_client::client_db::DbKeyPrefix::iter() {
                    match prefix {
                        fedimint_wallet_client::client_db::DbKeyPrefix::NextPegInTweakIndex => {
                            let next_peg_in_tweak = dbtx.get_value(&NextPegInTweakIndexKey).await;
                            ensure!(
                                next_peg_in_tweak.is_some(),
                                "validate_migrations was not able to read any peg in tweak index"
                            );
                            info!("Validated next peg in tweak index");
                        }
                    }
                }

                Ok(())
            },
            ModuleDecoderRegistry::from_iter([(
                LEGACY_HARDCODED_INSTANCE_ID_WALLET,
                WalletCommonInit::KIND,
                <Wallet as ServerModule>::decoder(),
            )]),
        )
        .await
    }
}

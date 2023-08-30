use std::time::{Duration, SystemTime};

use anyhow::{bail, Context};
use assert_matches::assert_matches;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{self, Secp256k1};
use fedimint_bitcoind::DynBitcoindRpc;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::Client;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, ModuleDatabaseTransaction};
use fedimint_core::task::sleep;
use fedimint_core::util::{BoxStream, NextOrPending};
use fedimint_core::{sats, Amount, Feerate, PeerId, ServerModule};
use fedimint_dummy_client::DummyClientGen;
use fedimint_dummy_common::config::DummyGenParams;
use fedimint_dummy_server::DummyGen;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::api::WalletFederationApi;
use fedimint_wallet_client::{
    DepositState, WalletClientExt, WalletClientGen, WalletClientModule, WithdrawState,
};
use fedimint_wallet_common::config::{WalletConfig, WalletGenParams};
use fedimint_wallet_common::tweakable::Tweakable;
use fedimint_wallet_common::txoproof::PegInProof;
use fedimint_wallet_common::{PegOutFees, Rbf};
use fedimint_wallet_server::WalletGen;
use futures::stream::StreamExt;
use miniscript::ToPublicKey;
use tracing::info;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientGen, DummyGen, DummyGenParams::default());
    let wallet_params = WalletGenParams::regtest(fixtures.bitcoin_server());
    let wallet_client = WalletClientGen::new(fixtures.bitcoin_client());
    fixtures.with_module(wallet_client, WalletGen, wallet_params)
}

fn bsats(satoshi: u64) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(satoshi)
}

const PEG_IN_AMOUNT_SATS: u64 = 5000;
const PEG_OUT_AMOUNT_SATS: u64 = 1000;
const PEG_IN_TIMEOUT: Duration = Duration::from_secs(60);

async fn peg_in<'a>(
    client: &'a Client,
    bitcoin: &dyn BitcoinTest,
    dyn_bitcoin_rpc: &DynBitcoindRpc,
    finality_delay: u64,
) -> anyhow::Result<BoxStream<'a, Amount>> {
    let valid_until = SystemTime::now() + PEG_IN_TIMEOUT;

    let mut balance_sub = client.subscribe_balance_changes().await;
    assert_eq!(balance_sub.ok().await?, sats(0));

    let (op, address) = client.get_deposit_address(valid_until).await?;
    let (_proof, tx) = bitcoin
        .send_and_mine_block(&address, bsats(PEG_IN_AMOUNT_SATS))
        .await;
    let height = dyn_bitcoin_rpc
        .get_tx_block_height(&tx.txid())
        .await?
        .context("expected tx to be mined")?;
    info!(?height, "Peg-in transaction mined");
    let sub = client.subscribe_deposit_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, DepositState::WaitingForTransaction);
    assert_eq!(sub.ok().await?, DepositState::WaitingForConfirmation);

    bitcoin.mine_blocks(finality_delay).await;
    assert_eq!(sub.ok().await?, DepositState::Confirmed);
    assert_eq!(sub.ok().await?, DepositState::Claimed);
    assert_eq!(client.get_balance().await, sats(PEG_IN_AMOUNT_SATS));
    assert_eq!(balance_sub.ok().await?, sats(PEG_IN_AMOUNT_SATS));

    Ok(balance_sub)
}

async fn await_consensus_to_catch_up(client: &Client, block_count: u64) -> anyhow::Result<u64> {
    let (_, instance) =
        client.get_first_module::<WalletClientModule>(&fedimint_wallet_client::KIND);
    loop {
        let current_consensus = client
            .api()
            .with_module(instance.id)
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
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let fees = client.get_withdraw_fee(address.clone(), peg_out).await?;
    let op = client.withdraw(address.clone(), peg_out, fees).await?;

    let balance_after_peg_out =
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS - fees.amount().to_sat());
    assert_eq!(client.get_balance().await, balance_after_peg_out);
    assert_eq!(balance_sub.ok().await?, balance_after_peg_out);

    let sub = client.subscribe_withdraw_updates(op).await?;
    let mut sub = sub.into_stream();
    assert_eq!(sub.ok().await?, WithdrawState::Created);
    let txid = match sub.ok().await? {
        WithdrawState::Succeeded(txid) => txid,
        other => panic!("Unexpected state: {other:?}"),
    };
    bitcoin.get_mempool_tx_fee(&txid).await;

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
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    // Peg-out test, requires block to recognize change UTXOs
    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);

    // Set invalid fees
    let fees = PegOutFees {
        fee_rate: Feerate { sats_per_kvb: 0 },
        total_weight: 0,
    };
    let op = client.withdraw(address.clone(), peg_out, fees).await?;
    assert_eq!(
        balance_sub.next().await.unwrap(),
        sats(PEG_IN_AMOUNT_SATS - PEG_OUT_AMOUNT_SATS)
    );

    let sub = client.subscribe_withdraw_updates(op).await?;
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

    let finality_delay = 10;
    bitcoin.mine_blocks(finality_delay).await;
    await_consensus_to_catch_up(&client, 1).await?;

    let mut balance_sub =
        peg_in(&client, bitcoin.as_ref(), &dyn_bitcoin_rpc, finality_delay).await?;

    let address = bitcoin.get_new_address().await;
    let peg_out = bsats(PEG_OUT_AMOUNT_SATS);
    let fees = client.get_withdraw_fee(address.clone(), peg_out).await?;
    let op = client.withdraw(address.clone(), peg_out, fees).await?;

    let sub = client.subscribe_withdraw_updates(op).await?;
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
    let op = client.rbf_withdraw(rbf.clone()).await?;
    let sub = client.subscribe_withdraw_updates(op).await?;
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
async fn peg_ins_that_are_unconfirmed_are_rejected() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let bitcoin = fixtures.bitcoin();
    let server_bitcoin_rpc_config = fixtures.bitcoin_server();
    let dyn_bitcoin_rpc = fixtures.dyn_bitcoin_rpc();
    let db = Database::new(MemDatabase::new(), Default::default());
    let mut task_group = fedimint_core::task::TaskGroup::new();
    let (wallet_server_cfg, _) = build_wallet_server_configs(server_bitcoin_rpc_config)?;

    let module_instance_id = 1;
    let root_secret =
        PlainRootSecretStrategy::to_root_secret(&PlainRootSecretStrategy::random(&mut OsRng));
    let secp = Secp256k1::new();
    let tweak_key = root_secret.to_secp_key(&secp);
    let x_only_pk = tweak_key.public_key().to_x_only_pubkey();
    let wallet_config: WalletConfig = wallet_server_cfg[0].to_typed()?;
    let peg_in_descriptor = wallet_config.consensus.peg_in_descriptor;

    let peg_in_address = peg_in_descriptor
        .tweak(&x_only_pk, secp256k1::SECP256K1)
        .address(wallet_config.consensus.network)?;

    let mut wallet = fedimint_wallet_server::Wallet::new_with_bitcoind(
        wallet_server_cfg[0].to_typed()?,
        db.clone(),
        dyn_bitcoin_rpc.clone(),
        &mut task_group,
    )
    .await?;

    let mut dbtx = db.begin_transaction().await;

    // Generate a minimum number of blocks before sending transactions
    bitcoin
        .mine_blocks(wallet_config.consensus.finality_delay.into())
        .await;

    let block_count = dyn_bitcoin_rpc.get_block_count().await?;
    sync_wallet_to_block(
        &mut dbtx.with_module_prefix(module_instance_id),
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
    let input = fedimint_wallet_common::WalletInput(Box::new(PegInProof::new(
        proof,
        transaction,
        output_index.try_into()?,
        x_only_pk,
    )?));

    match wallet
        .process_input(
            &mut dbtx.with_module_prefix(module_instance_id),
            &input,
            &fedimint_wallet_server::WalletVerificationCache,
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
        &mut dbtx.with_module_prefix(module_instance_id),
        &mut wallet,
        block_count.try_into()?,
    )
    .await?;

    assert_matches!(
        wallet
            .process_input(
                &mut dbtx.with_module_prefix(module_instance_id),
                &input,
                &fedimint_wallet_server::WalletVerificationCache,
            )
            .await,
        Ok(_)
    );
    dbtx.commit_tx().await;
    Ok(())
}

async fn sync_wallet_to_block(
    dbtx: &mut ModuleDatabaseTransaction<'_>,
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
        &WalletGen,
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
        <WalletGen as fedimint_core::module::ServerModuleInit>::kind(),
        fedimint_core::module::ModuleConsensusVersion(0),
        fedimint_core::module::ServerModuleInit::get_client_config(
            &WalletGen,
            &wallet_cfg[&PeerId::from(0)].consensus,
        )?,
    )?;
    Ok((wallet_cfg.into_values().collect(), client_cfg))
}

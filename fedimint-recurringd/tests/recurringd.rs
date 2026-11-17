use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::{Json, Router};
use fedimint_api_client::api::DynModuleApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::secp256k1::hashes::sha256;
use fedimint_core::secp256k1::{PublicKey, SECP256K1};
use fedimint_core::util::SafeUrl;
use fedimint_core::{BitcoinHash, sats};
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::common::gateway_endpoint_constants::GET_GATEWAY_ID_ENDPOINT;
use fedimint_ln_client::common::{LightningGateway, LightningGatewayAnnouncement};
use fedimint_ln_client::recurring::{PaymentCodeRootKey, RecurringPaymentProtocol};
use fedimint_ln_client::{
    LightningClientInit, LightningClientModule, MockGatewayConnection, tweak_user_key,
};
use fedimint_ln_server::LightningInit;
use fedimint_recurringd::RecurringInvoiceServer;
use fedimint_testing::fixtures::Fixtures;
use lightning_invoice::RoutingFees;
use rand::rngs::OsRng;

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);
    fixtures.with_module(
        LightningClientInit {
            gateway_conn: Some(Arc::new(MockGatewayConnection)),
        },
        LightningInit,
    )
}

/// recurringd's client probes a gateway's api before using it, so the
/// announcement needs this one live endpoint
async fn register_stub_gateway(ln_api: &DynModuleApi, gateway_id: PublicKey) -> anyhow::Result<()> {
    let router = Router::new().route(
        GET_GATEWAY_ID_ENDPOINT,
        get(move || async move { Json(gateway_id) }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let api = SafeUrl::parse(&format!("http://{}/", listener.local_addr()?))?;
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub gateway server failed");
    });

    ln_api
        .register_gateway(&LightningGatewayAnnouncement {
            info: LightningGateway {
                federation_index: 0,
                gateway_redeem_key: gateway_id,
                node_pub_key: gateway_id,
                lightning_alias: "stub gateway".to_string(),
                api,
                route_hints: vec![],
                fees: RoutingFees {
                    base_msat: 0,
                    proportional_millionths: 0,
                },
                gateway_id,
                supports_private_payments: false,
            },
            vetted: false,
            ttl: Duration::from_secs(600),
            auth: None,
        })
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn recipient_invoice_waits_for_offer_consensus() -> anyhow::Result<()> {
    let fixtures = fixtures();
    let fed = fixtures.new_fed_degraded().await;

    let client = fed.new_client().await;
    let ln_api = client
        .get_first_module::<LightningClientModule>()?
        .api
        .clone();
    let (_, gateway_id) = SECP256K1.generate_keypair(&mut OsRng);
    register_stub_gateway(&ln_api, gateway_id).await?;

    let recurringd = RecurringInvoiceServer::new(
        ConnectorRegistry::build_from_testing_env()?.bind().await?,
        MemDatabase::new(),
        SafeUrl::parse("http://127.0.0.1:8176/")?,
    )
    .await?;
    let federation_id = recurringd.register_federation(&fed.invite_code()).await?;

    let (_, root_public_key) = SECP256K1.generate_keypair(&mut OsRng);
    let root_key = PaymentCodeRootKey(root_public_key);
    recurringd
        .register_recurring_payment_code(
            federation_id,
            root_key,
            RecurringPaymentProtocol::LNURL,
            "[[\"text/plain\", \"test\"]]",
        )
        .await?;
    let payment_code_id = root_key.to_payment_code_id();

    // recurringd seeds the invoice index at 0 and advances before use, so the
    // first invoice is index 1
    let invoice_key = tweak_user_key(SECP256K1, root_public_key, 1);
    let preimage = sha256::Hash::hash(&invoice_key.serialize());
    let payment_hash = sha256::Hash::hash(preimage.as_ref());

    // snapshot the offer inside the task, at serve time: checked any later,
    // consensus catches up and the assertion goes vacuous
    let recipient = {
        let recurringd = recurringd.clone();
        let ln_api = ln_api.clone();
        tokio::spawn(async move {
            recurringd
                .await_invoice_index_generated(payment_code_id, 1)
                .await?;
            let offer_at_serve = ln_api.offer_exists(payment_hash).await?;
            anyhow::Ok(offer_at_serve)
        })
    };

    recurringd.lnurl_invoice(payment_code_id, sats(100)).await?;

    let offer_at_serve = tokio::time::timeout(Duration::from_secs(60), recipient).await???;
    assert!(
        offer_at_serve,
        "recipient endpoint served an invoice whose offer is not in consensus"
    );

    // ClientHandle::drop calls block_in_place, which is not allowed during
    // runtime shutdown, so keep the last handle alive past teardown
    std::mem::forget(recurringd);
    Ok(())
}

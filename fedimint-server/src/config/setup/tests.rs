use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use base64::Engine as _;
use bitcoin::Network;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::db::IRawDatabaseExt;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_server_core::setup_ui::ISetupApi;
use tokio::sync::mpsc::{self, Receiver};

use super::{ConfigGenOutcome, SetupApi, parse_backup};
use crate::config::io::{JSON_EXT, LOCAL_CONFIG};
use crate::config::{ConfigGenSettings, PeerSetupCode};

fn setup_api(network: Network) -> SetupApi {
    setup_api_with_version(network, "1.2.3-alpha")
}

fn setup_api_with_version(network: Network, version: &str) -> SetupApi {
    setup_api_with_version_and_receiver(network, version).0
}

fn setup_api_with_version_and_receiver(
    network: Network,
    version: &str,
) -> (SetupApi, Receiver<ConfigGenOutcome>) {
    let (sender, receiver) = mpsc::channel(1);
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    (
        SetupApi::new(
            ConfigGenSettings {
                p2p_bind: bind,
                api_bind: bind,
                ui_bind: bind,
                p2p_url: None,
                api_url: None,
                enable_iroh: true,
                iroh_dns: None,
                iroh_relays: Vec::new(),
                network,
                available_modules: BTreeSet::new(),
                default_modules: BTreeSet::new(),
            },
            MemDatabase::new().into_database(),
            sender,
            version.to_owned(),
            String::new(),
            None,
            None,
        ),
        receiver,
    )
}

const INVALID_RESTORE_BACKUP_FIXTURE_B64: &str =
    include_str!("../../test_fixtures/guardian-backup-invalid-config.tar.b64");

async fn setup_code(api: &SetupApi, name: &str) -> String {
    api.set_local_parameters(name.to_string(), None, None, None)
        .await
        .expect("setting local parameters should succeed")
}

fn decode_setup_code(setup_code: &str) -> PeerSetupCode {
    base32::decode_prefixed(FEDIMINT_PREFIX, setup_code).expect("setup code should decode")
}

#[tokio::test]
async fn accepts_peer_setup_code_with_matching_network() {
    let api = setup_api(Network::Regtest);
    let peer_api = setup_api(Network::Regtest);

    setup_code(&api, "local").await;
    let peer_code = setup_code(&peer_api, "peer").await;

    let added_peer = api
        .add_peer_setup_code(peer_code)
        .await
        .expect("peer setup code with matching network should be accepted");

    assert_eq!(added_peer, "peer");
}

#[test]
fn checked_in_backup_fixture_reaches_config_validation() {
    let backup = base64::prelude::BASE64_STANDARD
        .decode(INVALID_RESTORE_BACKUP_FIXTURE_B64.trim())
        .expect("checked-in backup fixture base64 should decode");
    let Err(err) = parse_backup(&backup, Some("pass")) else {
        panic!("invalid checked-in backup fixture should not restore");
    };

    assert!(
        err.to_string().contains("Reading restored config"),
        "unexpected restore error: {err:#}"
    );
}

#[test]
fn backup_restore_rejects_non_file_entries() {
    let mut backup = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut backup);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                PathBuf::from(LOCAL_CONFIG).with_extension(JSON_EXT),
                std::io::empty(),
            )
            .expect("writing tar entry should succeed");
        archive.finish().expect("finishing tar should succeed");
    }

    let Err(err) = parse_backup(&backup, None) else {
        panic!("non-file backup entries should be rejected");
    };

    assert!(
        err.to_string().contains("non-file entry"),
        "unexpected restore error: {err:#}"
    );
}

#[tokio::test]
async fn rejects_peer_setup_code_with_different_network() {
    let api = setup_api(Network::Regtest);
    let peer_api = setup_api(Network::Signet);

    setup_code(&api, "local").await;
    let peer_code = setup_code(&peer_api, "peer").await;

    let err = api
        .add_peer_setup_code(peer_code)
        .await
        .expect_err("peer setup code with different network should be rejected");

    assert!(
        err.to_string()
            .contains("Guardian uses Bitcoin network signet but we use regtest")
    );
}

#[tokio::test]
async fn rejects_peer_setup_code_from_different_fedimint_minor() {
    let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha");
    let peer_api = setup_api_with_version(Network::Regtest, "1.3.0-beta");

    setup_code(&api, "local").await;
    let peer_code = setup_code(&peer_api, "peer").await;

    let err = api
        .add_peer_setup_code(peer_code)
        .await
        .expect_err("peer setup code from a different Fedimint minor should be rejected");

    assert!(
        err.to_string()
            .contains("Guardian uses Fedimint version 1.3.0 but we use 1.2.3")
    );
}

#[tokio::test]
async fn accepts_peer_setup_code_from_same_vendor_with_patch_skew() {
    let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha+fedi");
    let peer_api = setup_api_with_version(Network::Regtest, "1.2.4-beta+fedi");

    let local_code = setup_code(&api, "local").await;
    let peer_code = setup_code(&peer_api, "peer").await;
    let peer_setup_code = decode_setup_code(&peer_code);

    let added_peer = api
        .add_peer_setup_code(peer_code)
        .await
        .expect("peer setup code from the same Fedimint minor should be accepted");

    assert_eq!(added_peer, "peer");
    assert_eq!(
        decode_setup_code(&local_code).fedimint_version.to_string(),
        "1.2.3+fedi"
    );
    assert_eq!(peer_setup_code.fedimint_version.to_string(), "1.2.4+fedi");
}

#[tokio::test]
async fn rejects_peer_setup_code_from_different_fedimint_vendor() {
    for (local_version, peer_version) in [("1.2.3+fedi", "1.2.4"), ("1.2.3+fedi", "1.2.4+acme")] {
        let api = setup_api_with_version(Network::Regtest, local_version);
        let peer_api = setup_api_with_version(Network::Regtest, peer_version);

        setup_code(&api, "local").await;
        let peer_code = setup_code(&peer_api, "peer").await;

        let err = api
            .add_peer_setup_code(peer_code)
            .await
            .expect_err("peer setup code from a different vendor should be rejected");

        assert!(
            err.to_string()
                .contains(&format!("Guardian uses Fedimint version {peer_version}"))
        );
    }
}

#[tokio::test]
async fn rejects_malformed_local_fedimint_version() {
    let malformed_local = setup_api_with_version(Network::Regtest, "fedimint-code-version");
    let err = malformed_local
        .set_local_parameters("local".to_owned(), None, None, None)
        .await
        .expect_err("malformed local version should be rejected");
    assert!(err.to_string().contains("Invalid local Fedimint version"));
}

#[tokio::test]
async fn rejects_different_fedimint_minor_during_dkg() {
    let api = setup_api_with_version(Network::Regtest, "1.2.3-alpha");
    let peer_api = setup_api_with_version(Network::Regtest, "1.3.0-beta");

    setup_code(&api, "local").await;
    let peer_code = setup_code(&peer_api, "peer").await;
    let peer_code = base32::decode_prefixed(FEDIMINT_PREFIX, &peer_code)
        .expect("peer setup code should decode");

    api.state.lock().await.setup_codes.insert(peer_code);

    let err = api
        .start_dkg()
        .await
        .expect_err("DKG should reject a peer from a different Fedimint minor");

    assert!(
        err.to_string()
            .contains("Guardian uses Fedimint version 1.3.0 but we use 1.2.3")
    );
}

#[tokio::test]
async fn accepts_same_vendor_patch_versions_during_dkg() {
    let (api, mut receiver) =
        setup_api_with_version_and_receiver(Network::Regtest, "1.2.3-alpha+fedi");
    api.set_local_parameters("local".to_owned(), None, None, Some(4))
        .await
        .expect("setting local parameters should succeed");

    for (name, version) in [
        ("peer-1", "1.2.4-beta+fedi"),
        ("peer-2", "1.2.5+fedi"),
        ("peer-3", "1.2.6-rc.1+fedi"),
    ] {
        let peer_api = setup_api_with_version(Network::Regtest, version);
        let peer_code = setup_code(&peer_api, name).await;
        let peer_code = decode_setup_code(&peer_code);
        api.state.lock().await.setup_codes.insert(peer_code);
    }

    api.start_dkg()
        .await
        .expect("DKG should accept peers from the same Fedimint minor");
    receiver
        .recv()
        .await
        .expect("DKG parameters should be sent");
}

#[tokio::test]
async fn rejects_different_fedimint_vendor_during_dkg() {
    for (local_version, peer_version) in [("1.2.3+fedi", "1.2.4"), ("1.2.3+fedi", "1.2.4+acme")] {
        let api = setup_api_with_version(Network::Regtest, local_version);
        let peer_api = setup_api_with_version(Network::Regtest, peer_version);

        setup_code(&api, "local").await;
        let peer_code = decode_setup_code(&setup_code(&peer_api, "peer").await);
        api.state.lock().await.setup_codes.insert(peer_code);

        let err = api
            .start_dkg()
            .await
            .expect_err("DKG should reject a peer from a different vendor");
        assert!(
            err.to_string()
                .contains(&format!("Guardian uses Fedimint version {peer_version}"))
        );
    }
}

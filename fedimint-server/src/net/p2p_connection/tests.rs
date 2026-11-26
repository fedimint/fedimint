use bytes::BytesMut;
use fedimint_core::encoding::Encodable as _;
use fedimint_server_core::dashboard_ui::ConnectionType;

use super::{IP2PFrame, IrohPath, IrohPathKind, connection_type_from_paths};

#[tokio::test]
async fn reads_consensus_and_legacy_frames() {
    let message = 65_536u64;
    let consensus = message.consensus_encode_to_vec();
    let legacy = bincode::serialize(&message).expect("serialize legacy message");
    let mut legacy_with_trailing = legacy.clone();
    legacy_with_trailing.push(0);

    for bytes in [consensus, legacy, legacy_with_trailing] {
        let mut frame = BytesMut::from(bytes.as_slice());
        assert_eq!(
            IP2PFrame::<u64>::read_to_end(&mut frame)
                .await
                .expect("decode frame"),
            message
        );
    }
}

#[tokio::test]
async fn limits_legacy_reads_to_the_frame_size() {
    let mut bytes = bincode::serialize(&65_536u64).expect("serialize legacy message");
    bytes.truncate(bytes.len() - 1);
    let mut frame = BytesMut::from(bytes.as_slice());
    let error = IP2PFrame::<u64>::read_to_end(&mut frame)
        .await
        .expect_err("truncated legacy frame must fail");

    assert!(
        matches!(
            error.downcast_ref::<bincode::Error>().map(Box::as_ref),
            Some(bincode::ErrorKind::SizeLimit)
        ),
        "expected a legacy size-limit error, got {error:#}"
    );
}

#[test]
fn maps_only_selected_iroh_paths_to_dashboard_connection_types() {
    let selected = |kind| IrohPath {
        selected: true,
        kind,
    };
    let unselected = |kind| IrohPath {
        selected: false,
        kind,
    };

    assert_eq!(
        connection_type_from_paths([
            selected(IrohPathKind::Direct),
            unselected(IrohPathKind::Relay),
        ]),
        Some(ConnectionType::Direct)
    );
    assert_eq!(
        connection_type_from_paths([
            unselected(IrohPathKind::Direct),
            selected(IrohPathKind::Relay),
        ]),
        Some(ConnectionType::Relay)
    );
    assert_eq!(
        connection_type_from_paths([
            selected(IrohPathKind::Direct),
            selected(IrohPathKind::Relay),
        ]),
        Some(ConnectionType::Mixed)
    );
    assert_eq!(
        connection_type_from_paths([
            unselected(IrohPathKind::Direct),
            unselected(IrohPathKind::Relay),
            selected(IrohPathKind::Unknown),
        ]),
        None
    );
}

use fedimint_server_core::dashboard_ui::ConnectionType;

use super::{IrohPath, IrohPathKind, connection_type_from_paths};

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

use super::{LOW, RootData, port_range};

#[test]
fn root_data_sanity() {
    let mut data = RootData::default();

    data.insert(2..4);
    data.insert(6..8);
    data.insert(100..108);
    assert_eq!(data.contains(0..2), None);
    assert_eq!(data.contains(0..3), Some(4));
    assert_eq!(data.contains(2..4), Some(4));
    assert_eq!(data.contains(3..4), Some(4));
    assert_eq!(data.contains(3..5), Some(4));
    assert_eq!(data.contains(4..6), None);
    assert_eq!(data.contains(0..10), Some(8));
    assert_eq!(data.contains(6..10), Some(8));
    assert_eq!(data.contains(7..8), Some(8));
    assert_eq!(data.contains(8..10), None);
}

#[test]
fn port_range_rejects_unrepresentable_endpoints() {
    assert!(port_range(LOW, u16::MAX).is_err());
}

#[test]
fn port_range_accepts_representable_endpoints() {
    assert_eq!(port_range(LOW, 3).expect("range should fit"), LOW..10003);
    assert_eq!(
        port_range(LOW, u16::MAX - LOW).expect("range endpoint should fit exactly"),
        LOW..u16::MAX
    );
}

#[test]
fn failed_range_allocation_does_not_reserve_ports() {
    let mut data = RootData::default();

    assert!(data.get_free_port_range(u16::MAX).is_err());
    assert!(data.keys.is_empty());
    assert_eq!(data.next, LOW);
}

#[test]
fn range_allocation_checks_each_candidate_endpoint() {
    let mut data = RootData::default();
    data.insert(LOW..LOW + 1);
    data.next = LOW;

    assert!(data.get_free_port_range(u16::MAX - LOW).is_err());
    assert_eq!(data.keys.len(), 1);
    assert!(data.keys.contains_key(&LOW));
}

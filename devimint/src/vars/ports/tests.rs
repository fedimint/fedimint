use super::PortRange;

#[test]
fn take_hands_out_contiguous_ports() {
    let mut ports = PortRange::from_base(20_000, 5);

    assert_eq!(ports.take(1).expect("first port fits"), 20_000);
    assert_eq!(ports.take(3).expect("three ports fit"), 20_001);
    assert_eq!(ports.take(1).expect("last port fits"), 20_004);
}

#[test]
fn take_rejects_requests_past_the_end() {
    let mut ports = PortRange::from_base(20_000, 2);

    ports.take(1).expect("first port fits");
    let error = ports
        .take(2)
        .expect_err("two ports do not fit in the one remaining")
        .to_string();

    assert!(error.contains("2 ports requested, 1 left"));
    assert_eq!(
        ports.take(1).expect("failed take leaves range unchanged"),
        20_001
    );
}

#[test]
fn take_rejects_overflow_past_u16_max() {
    let mut ports = PortRange::from_base(u16::MAX, 10);

    ports
        .take(2)
        .expect_err("range must not wrap past u16::MAX");
}

use super::release_version;

#[test]
fn release_version_ignores_pre_release_and_build_metadata() {
    assert_eq!(release_version("1.2.3-alpha.1"), "1.2.3");
    assert_eq!(release_version("1.2.3-beta"), "1.2.3");
    assert_eq!(release_version("1.2.3-rc.1"), "1.2.3");
    assert_eq!(release_version("1.2.3+vendor-a"), "1.2.3");
    assert_eq!(release_version("1.2.3-alpha.1+vendor-a"), "1.2.3");
}

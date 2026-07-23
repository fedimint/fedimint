use fedimint_core::module::{ApiEndpoint, ApiVersion, MultiApiVersion, serde_json};

use super::api_versions_from_endpoints;

fn make_endpoint(major: u32, minor: u32) -> ApiEndpoint<()> {
    ApiEndpoint {
        path: "/fake",
        version: ApiVersion::new(major, minor),
        handler: Box::new(|_, _, _| Box::pin(async { Ok(serde_json::Value::Null) })),
    }
}

#[test]
fn version_derived_from_endpoints_max_minor() {
    let endpoints = vec![
        make_endpoint(0, 1),
        make_endpoint(0, 3),
        make_endpoint(0, 2),
        make_endpoint(1, 0),
    ];

    let expected = MultiApiVersion::try_from_iter([ApiVersion::new(0, 3), ApiVersion::new(1, 0)])
        .expect("test versions have unique majors");

    assert_eq!(api_versions_from_endpoints(endpoints), expected);
}

#[test]
fn version_derived_from_empty_endpoints_defaults_to_zero() {
    let expected = MultiApiVersion::try_from_iter([ApiVersion::new(0, 0)])
        .expect("test versions have unique majors");

    assert_eq!(
        api_versions_from_endpoints(Vec::<ApiEndpoint<()>>::new()),
        expected
    );
}

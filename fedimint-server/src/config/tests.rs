use fedimint_core::module::{ApiEndpoint, ApiVersion};
use fedimint_server_core::DynServerModule;

use super::api_versions_from_endpoints;

fn make_endpoint(major: u32, minor: u32) -> ApiEndpoint<DynServerModule> {
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
        make_endpoint(0, 3), // highest minor for major 0
        make_endpoint(0, 2),
        make_endpoint(1, 0), // separate major
    ];

    let expected = fedimint_core::module::MultiApiVersion::try_from_iter([
        ApiVersion::new(0, 3),
        ApiVersion::new(1, 0),
    ])
    .expect("test versions have unique majors");

    assert_eq!(api_versions_from_endpoints(endpoints), expected);
}

#[test]
fn version_derived_from_empty_endpoints_defaults_to_zero() {
    let expected = fedimint_core::module::MultiApiVersion::try_from_iter([ApiVersion::new(0, 0)])
        .expect("test versions have unique majors");

    assert_eq!(api_versions_from_endpoints(vec![]), expected);
}

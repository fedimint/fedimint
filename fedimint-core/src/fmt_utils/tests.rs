use super::AbbreviateJson;

#[test]
fn sanity_check_abbreviate_json() {
    for v in [
        serde_json::json!(null),
        serde_json::json!(true),
        serde_json::json!(false),
        serde_json::json!("foo"),
        serde_json::json!({}),
        serde_json::json!([]),
        serde_json::json!([1]),
        serde_json::json!([1, 3, 4]),
        serde_json::json!({"a": "b"}),
        serde_json::json!({"a": "b", "c": "d"}),
        serde_json::json!({"a": { "foo": "bar"}, "c": "d"}),
        serde_json::json!({"a": [1, 2, 3, 4], "b": {"c": "d"}}),
        serde_json::json!([{"a": "b"}]),
        serde_json::json!([{"a": "b"}, {"d": "f"}]),
        serde_json::json!([null]),
    ] {
        assert_eq!(format!("{:?}", &v), format!("{:?}", AbbreviateJson(&v)));
    }
}

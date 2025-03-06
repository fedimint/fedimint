use std::rc::Rc;

use jaq_json::Val;

use crate::feerate_source::FetchJson;

fn val_str(s: &str) -> Val {
    Val::Str(Rc::new(s.to_owned()))
}

#[test]
fn test_filter() {
    let source_id = FetchJson::from_str("https://example.com#.").expect("Failed to parse url");
    assert_eq!(
        source_id
            .apply_filter(serde_json::json!("foo"))
            .expect("Failed to apply filter"),
        val_str("foo")
    );

    let source_access_member =
        FetchJson::from_str("https://example.com#.[0].foo").expect("Failed to parse url");
    assert_eq!(
        source_access_member
            .apply_filter(serde_json::json!([{"foo": "bar"}, 1, 2, 3]))
            .expect("Failed to apply filter"),
        val_str("bar")
    );
}

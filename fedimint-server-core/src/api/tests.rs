use super::validate_page_range;

#[test]
fn accepts_empty_partial_and_full_pages() {
    assert!(validate_page_range((10, 10), 4).is_ok());
    assert!(validate_page_range((10, 12), 4).is_ok());
    assert!(validate_page_range((10, 14), 4).is_ok());
}

#[test]
fn rejects_invalid_page_bounds_with_bad_request() {
    assert_eq!(validate_page_range((11, 10), 4).unwrap_err().code, 400);
    assert_eq!(validate_page_range((10, 15), 4).unwrap_err().code, 400);
}

use fedimint_core::module::{ApiError, ApiResult};

#[cfg(test)]
mod tests;

/// Validates a half-open page range, allowing empty pages.
pub fn validate_page_range((start, end): (u64, u64), max_size: u64) -> ApiResult<()> {
    let size = end
        .checked_sub(start)
        .ok_or_else(|| ApiError::bad_request("Page start must not exceed page end".to_owned()))?;
    if size > max_size {
        return Err(ApiError::bad_request(format!(
            "Page size must not exceed {max_size}"
        )));
    }
    Ok(())
}

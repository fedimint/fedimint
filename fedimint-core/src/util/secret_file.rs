//! Explicit, bounded file/stdin inputs for command-line secrets.

use std::io::Read;
use std::path::Path;

/// A secret input failure without secret-bearing diagnostic context.
#[derive(Debug, thiserror::Error)]
pub enum SecretInputError {
    /// The input file could not be opened.
    #[error("Could not open secret input file")]
    Open,
    /// Reading the input failed.
    #[error("Could not read secret input")]
    Read,
    /// The configured size limit cannot be represented.
    #[error("Invalid secret input size limit")]
    InvalidLimit,
    /// The input exceeded its configured limit.
    #[error("Secret input exceeds size limit")]
    TooLarge,
    /// The input was not UTF-8.
    #[error("Secret input is not valid UTF-8")]
    InvalidUtf8,
    /// More than one input would consume standard input.
    #[error("Only one secret input may read standard input")]
    MultipleStdin,
}

/// Read UTF-8 secret material from a file, or standard input when `path` is
/// `-`.
///
/// The limit includes the optional final line ending. Exactly one final LF,
/// optionally preceded by CR, is removed; all other whitespace is preserved.
/// Errors deliberately omit paths, contents, and underlying error messages.
///
/// Callers must check all input sources for conflicts before reading, including
/// [`ensure_single_stdin`]. Noninteractive daemons must reject `-` themselves.
/// Parsing the returned value must not expose its contents in diagnostics.
pub fn read_secret_file(path: &Path, max_bytes: usize) -> Result<String, SecretInputError> {
    if path == Path::new("-") {
        read_secret(std::io::stdin().lock(), max_bytes)
    } else {
        let file = std::fs::File::open(path).map_err(|_| SecretInputError::Open)?;
        read_secret(file, max_bytes)
    }
}

/// Reject multiple consumers of standard input before any secret is read.
pub fn ensure_single_stdin<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), SecretInputError> {
    if paths
        .into_iter()
        .filter(|path| *path == Path::new("-"))
        .take(2)
        .count()
        > 1
    {
        return Err(SecretInputError::MultipleStdin);
    }
    Ok(())
}

fn read_secret(reader: impl Read, max_bytes: usize) -> Result<String, SecretInputError> {
    let limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(SecretInputError::InvalidLimit)?;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretInputError::Read)?;
    if bytes.len() > max_bytes {
        return Err(SecretInputError::TooLarge);
    }
    let mut value = String::from_utf8(bytes).map_err(|_| SecretInputError::InvalidUtf8)?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests;

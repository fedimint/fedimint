use std::fmt::Formatter;
use std::{error, fmt};

/// A wrapper with `fmt::Display` for any `E : Error` that will print chain
/// of causes
pub struct FmtErrorCompact<'e, E>(pub &'e E);

impl<E> fmt::Display for FmtErrorCompact<'_, E>
where
    E: error::Error,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut source_opt: Option<&dyn std::error::Error> = Some(self.0);

        while source_opt.is_some() {
            let source = source_opt.take().expect("Just checked");
            f.write_fmt(format_args!("{source}"))?;

            source_opt = source.source();
            if source_opt.is_some() {
                f.write_str(": ")?;
            }
        }
        Ok(())
    }
}

/// A wrapper with `fmt::Display` for [`anyhow::Error`] that will print
/// chain of causes
pub struct FmtCompactErrorAnyhow<'e>(pub &'e anyhow::Error);

impl fmt::Display for FmtCompactErrorAnyhow<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // <https://docs.rs/anyhow/latest/anyhow/struct.Error.html#display-representations>
        f.write_fmt(format_args!("{:#}", self.0))
    }
}

/// Simple utility trait to print error chains
pub trait FmtCompact<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact(self) -> Self::Report;
}

/// Simple utility trait to print error chains (for [`anyhow::Error`])
pub trait FmtCompactAnyhow<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact_anyhow(self) -> Self::Report;
}

impl<'e, E> FmtCompact<'e> for &'e E
where
    E: error::Error,
{
    type Report = FmtErrorCompact<'e, E>;

    fn fmt_compact(self) -> Self::Report {
        FmtErrorCompact(self)
    }
}

impl<'e> FmtCompactAnyhow<'e> for &'e anyhow::Error {
    type Report = FmtCompactErrorAnyhow<'e>;

    fn fmt_compact_anyhow(self) -> Self::Report {
        FmtCompactErrorAnyhow(self)
    }
}

/// A wrapper with `fmt::Display` for `Result<T, E>` where `E: Error` that
/// prints the error chain on `Err` or `-` on `Ok`
pub struct FmtCompactResultDisplay<'a, T, E>(pub &'a Result<T, E>);

impl<T, E: error::Error> fmt::Display for FmtCompactResultDisplay<'_, T, E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(_) => f.write_str("-"),
            Err(e) => FmtErrorCompact(e).fmt(f),
        }
    }
}

/// A wrapper with `fmt::Display` for `Result<T, anyhow::Error>` that
/// prints the error chain on `Err` or `-` on `Ok`
pub struct FmtCompactResultAnyhowDisplay<'a, T>(pub &'a Result<T, anyhow::Error>);

impl<T> fmt::Display for FmtCompactResultAnyhowDisplay<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(_) => f.write_str("-"),
            Err(e) => FmtCompactErrorAnyhow(e).fmt(f),
        }
    }
}

/// Extension trait to format `Result<T, E>` compactly (for `E: Error`)
pub trait FmtCompactResult<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact_result(&'a self) -> Self::Report;
}

/// Extension trait to format `Result<T, anyhow::Error>` compactly
pub trait FmtCompactResultAnyhow<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact_result_anyhow(&'a self) -> Self::Report;
}

impl<'a, T, E> FmtCompactResult<'a> for Result<T, E>
where
    E: error::Error + 'a,
    T: 'a,
{
    type Report = FmtCompactResultDisplay<'a, T, E>;

    fn fmt_compact_result(&'a self) -> Self::Report {
        FmtCompactResultDisplay(self)
    }
}

impl<'a, T: 'a> FmtCompactResultAnyhow<'a> for Result<T, anyhow::Error> {
    type Report = FmtCompactResultAnyhowDisplay<'a, T>;

    fn fmt_compact_result_anyhow(&'a self) -> Self::Report {
        FmtCompactResultAnyhowDisplay(self)
    }
}

#[cfg(test)]
mod test;

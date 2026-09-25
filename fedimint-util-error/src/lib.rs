use std::fmt::Formatter;
use std::{error, fmt};

/// A wrapper with `fmt::Display` for any `E : Error`, unsized ones such as
/// `dyn Error` included, that prints the error and its chain of causes,
/// joined with `": "`
pub struct FmtErrorCompact<'e, E>(pub &'e E)
where
    E: ?Sized;

impl<E> fmt::Display for FmtErrorCompact<'_, E>
where
    E: error::Error + ?Sized,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;

        let mut source = self.0.source();
        while let Some(error) = source {
            write!(f, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}

/// Simple utility trait to print error chains
///
/// Implemented for a reference to any error, `dyn Error` included, so method
/// calls also reach the error behind a `Box<dyn Error>` or any other pointer
/// that derefs to one.
pub trait FmtCompact<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact(self) -> Self::Report;
}

impl<'e, E> FmtCompact<'e> for &'e E
where
    E: error::Error + ?Sized,
{
    type Report = FmtErrorCompact<'e, E>;

    fn fmt_compact(self) -> Self::Report {
        FmtErrorCompact(self)
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

/// Extension trait to format `Result<T, E>` compactly (for `E: Error`)
pub trait FmtCompactResult<'a> {
    type Report: fmt::Display + 'a;
    fn fmt_compact_result(&'a self) -> Self::Report;
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

#[cfg(test)]
mod test;

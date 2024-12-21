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
        let mut source_opt: Option<&(dyn std::error::Error)> = Some(self.0);

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

#[cfg(test)]
mod test {
    use std::io;

    use anyhow::Context as _;

    use super::*;

    #[test]
    pub(crate) fn fmt_compact_anyhow_sanity() {
        fn foo() -> anyhow::Result<()> {
            anyhow::bail!("Foo")
        }

        fn bar() -> anyhow::Result<()> {
            foo().context("xyz")?;
            unreachable!()
        }

        let Err(err) = bar() else {
            panic!("abc");
        };
        assert_eq!(err.fmt_compact_anyhow().to_string(), "xyz: Foo");
    }

    #[test]
    pub(crate) fn fmt_compact_sanity() {
        fn foo() -> Result<(), io::Error> {
            Err(io::Error::other("d"))
        }

        #[derive(Debug)]
        struct BarError {
            inner: io::Error,
        }

        impl std::error::Error for BarError {
            fn source(&self) -> Option<&(dyn error::Error + 'static)> {
                Some(&self.inner)
            }
        }

        impl fmt::Display for BarError {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("BarError")
            }
        }

        fn bar() -> Result<(), BarError> {
            Err(BarError {
                inner: foo().expect_err("wat"),
            })?;
            unreachable!()
        }

        let Err(err) = bar() else {
            panic!("abc");
        };
        assert_eq!(err.fmt_compact().to_string(), "BarError: d");
    }
}

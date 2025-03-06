use std::io;

use anyhow::Context as _;

use super::{FmtCompact, FmtCompactAnyhow, Formatter, error, fmt};

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

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

#[test]
pub(crate) fn fmt_compact_result_anyhow_sanity() {
    use super::FmtCompactResultAnyhow as _;

    fn foo() -> anyhow::Result<()> {
        anyhow::bail!("Foo")
    }

    fn bar() -> anyhow::Result<()> {
        foo().context("xyz")?;
        unreachable!()
    }

    let ok_result: anyhow::Result<i32> = Ok(42);
    assert_eq!(ok_result.fmt_compact_result_anyhow().to_string(), "-");

    let err_result = bar();
    assert_eq!(
        err_result.fmt_compact_result_anyhow().to_string(),
        "xyz: Foo"
    );
}

#[test]
pub(crate) fn fmt_compact_result_sanity() {
    use super::FmtCompactResult as _;

    let ok_result: Result<i32, io::Error> = Ok(42);
    assert_eq!(ok_result.fmt_compact_result().to_string(), "-");

    let err_result: Result<i32, io::Error> = Err(io::Error::other("d"));
    assert_eq!(err_result.fmt_compact_result().to_string(), "d");
}

#[test]
fn fmt_compact_walks_the_chain_of_an_unsized_error() {
    #[derive(Debug)]
    struct OuterError {
        inner: io::Error,
    }

    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            Some(&self.inner)
        }
    }

    impl fmt::Display for OuterError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }

    let boxed: Box<dyn error::Error + Send + Sync> = Box::new(OuterError {
        inner: io::Error::other("inner"),
    });
    assert_eq!(boxed.fmt_compact().to_string(), "outer: inner");

    let unsized_ref: &dyn error::Error = &*boxed;
    assert_eq!(unsized_ref.fmt_compact().to_string(), "outer: inner");
}

/// `anyhow::Error` derefs to its `dyn Error`, whose chain `fmt_compact`
/// prints exactly like anyhow's alternate Display. Goes with the anyhow
/// dependency.
#[test]
fn fmt_compact_prints_anyhow_chains_like_the_alternate_display() {
    #[derive(Debug)]
    struct OuterError(io::Error);

    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            Some(&self.0)
        }
    }

    impl fmt::Display for OuterError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }

    let context_chain = anyhow::Error::from(io::Error::other("inner"))
        .context("middle")
        .context("outer");
    let wrapped_std = anyhow::Error::from(OuterError(io::Error::other("inner")));
    let context_on_std = anyhow::Error::from(OuterError(io::Error::other("inner"))).context("ctx");
    let message = anyhow::anyhow!("plain {}", 1);

    for err in [&context_chain, &wrapped_std, &context_on_std, &message] {
        assert_eq!(err.fmt_compact().to_string(), format!("{err:#}"));
    }
    assert_eq!(
        context_chain.fmt_compact().to_string(),
        "outer: middle: inner"
    );
    assert_eq!(
        context_on_std.fmt_compact().to_string(),
        "ctx: outer: inner"
    );
}

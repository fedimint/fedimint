use std::io;

use super::{FmtCompact, Formatter, error, fmt};

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

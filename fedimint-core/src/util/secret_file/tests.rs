use std::io::{self, Read};
use std::path::Path;

use super::{ensure_single_stdin, read_secret, read_secret_file};

#[test]
fn preserves_everything_except_one_line_ending() {
    for (input, expected) in [
        ("", ""),
        (" secret ", " secret "),
        ("secret\n", "secret"),
        ("secret\r\n", "secret"),
        ("secret\r", "secret\r"),
        ("secret\n\n", "secret\n"),
        ("secret \r\n", "secret "),
    ] {
        assert_eq!(read_secret(input.as_bytes(), 1024).unwrap(), expected);
    }
}

#[test]
fn bounded_and_utf8_checked() {
    assert_eq!(read_secret(&b"1234"[..], 4).unwrap(), "1234");
    assert!(read_secret(&b"1234\n"[..], 4).is_err());
    assert!(read_secret(&[0xff][..], 4).is_err());
    assert_eq!(read_secret(&b""[..], 0).unwrap(), "");
    assert!(read_secret(&b"x"[..], 0).is_err());
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive underlying error"))
    }
}

#[test]
fn errors_do_not_include_input_or_underlying_errors() {
    for error in [
        read_secret(FailingReader, 1024).unwrap_err(),
        read_secret(&b"sensitive value"[..], 1).unwrap_err(),
        read_secret(&b"sensitive \xff"[..], 1024).unwrap_err(),
        read_secret_file(Path::new("/nonexistent/sensitive-path"), 1024).unwrap_err(),
    ] {
        assert!(!format!("{error:#}").contains("sensitive"));
        assert!(!format!("{error:?}").contains("sensitive"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn rejects_multiple_stdin_inputs() {
    assert!(ensure_single_stdin([]).is_ok());
    assert!(ensure_single_stdin([Path::new("-"), Path::new("file")]).is_ok());
    assert!(ensure_single_stdin([Path::new("-"), Path::new("-")]).is_err());
}

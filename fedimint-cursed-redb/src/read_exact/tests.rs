use super::read_exact_at;

#[test]
fn retries_positive_short_reads() {
    let source = [1, 2, 3, 4];
    let mut out = [0; 4];

    read_exact_at(10, &mut out, |offset, remaining| {
        let source_offset = usize::try_from(offset - 10).expect("offset fits in usize");
        let read_len = remaining.len().min(2);
        remaining[..read_len].copy_from_slice(&source[source_offset..source_offset + read_len]);
        Ok(read_len)
    })
    .expect("short reads make progress");

    assert_eq!(out, source);
}

#[test]
fn empty_read_succeeds_without_accessing_source() {
    read_exact_at(0, &mut [], |_, _| -> std::io::Result<usize> {
        panic!("empty reads must not access the source")
    })
    .expect("empty read succeeds");
}

#[test]
fn zero_progress_returns_unexpected_eof() {
    let mut out = [0; 4];
    let mut read_calls = 0;

    let error = read_exact_at(0, &mut out, |_, remaining| {
        read_calls += 1;
        match read_calls {
            1 => {
                remaining[..2].copy_from_slice(&[1, 2]);
                Ok(2)
            }
            2 => Ok(0),
            _ => panic!("read retried after making zero progress"),
        }
    })
    .expect_err("zero progress before filling the output is EOF");

    assert_eq!(read_calls, 2);
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert_eq!(out, [1, 2, 0, 0]);
}

#[test]
fn source_errors_are_preserved() {
    let mut out = [0; 1];

    let error = read_exact_at(0, &mut out, |_, _| {
        Err(std::io::Error::other("source failure"))
    })
    .expect_err("source error is returned");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(error.to_string(), "source failure");
}

use std::io;

pub(crate) fn read_exact_at(
    offset: u64,
    out: &mut [u8],
    mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
    let mut bytes_read = 0;
    while bytes_read != out.len() {
        assert!(bytes_read < out.len());

        let read = read(offset + bytes_read as u64, &mut out[bytes_read..])?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes_read += read;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

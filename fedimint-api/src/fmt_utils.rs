use std::fmt;

/// Use for displaying bytes in the logs
pub struct AbbreviateHexBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Display for AbbreviateHexBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 64 {
            f.write_str(&hex::encode(self.0))?;
        } else {
            f.write_str(&hex::encode(&self.0[..64]))?;
            f.write_fmt(format_args!("-{}", self.0.len()))?;
        }
        Ok(())
    }
}

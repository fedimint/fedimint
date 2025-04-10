use std::fmt;

pub struct FmtOption<'r, O>(pub Option<&'r O>);

impl<O> fmt::Display for FmtOption<'_, O>
where
    O: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(o) => o.fmt(f),
            None => f.write_str("-"),
        }
    }
}

pub trait AsFmtOption {
    type Fmt: fmt::Display;
    fn fmt_option(self) -> Self::Fmt;
}

impl<'e, O> AsFmtOption for &'e Option<O>
where
    O: fmt::Display,
{
    type Fmt = FmtOption<'e, O>;

    fn fmt_option(self) -> Self::Fmt {
        FmtOption(self.as_ref())
    }
}

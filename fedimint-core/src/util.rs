use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

use url::Url;

// TODO: make fully RFC1738 conformant
/// Wrapper for `Url` that only prints the scheme, domain, port and path portion
/// of a `Url` in its `Display` implementation. This is useful to hide private
/// information like user names and passwords in logs or UIs.
///
/// The output is not fully RFC1738 conformant but good enough for our current
/// purposes.
pub struct SanitizedUrl<'a>(Cow<'a, Url>);

impl<'a> SanitizedUrl<'a> {
    pub fn new_owned(url: Url) -> SanitizedUrl<'static> {
        SanitizedUrl(Cow::Owned(url))
    }

    pub fn new_borrowed(url: &'a Url) -> SanitizedUrl<'a> {
        SanitizedUrl(Cow::Borrowed(url))
    }
}

impl<'a> Display for SanitizedUrl<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.0.scheme())?;

        if let Some(host) = self.0.host_str() {
            write!(f, "{host}")?;
        }

        if let Some(port) = self.0.port() {
            write!(f, ":{port}")?;
        }

        write!(f, "{}", self.0.path())?;

        Ok(())
    }
}

impl<'a> Debug for SanitizedUrl<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SanitizedUrl(")?;
        Display::fmt(self, f)?;
        write!(f, ", has_password={}", self.0.password().is_some())?;
        write!(f, ", has_username={}", !self.0.username().is_empty())?;
        write!(f, ")")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::util::SanitizedUrl;

    #[test]
    fn test_sanitized_url() {
        let test_cases = vec![
            ("http://1.2.3.4:80/foo", "http://1.2.3.4/foo", "SanitizedUrl(http://1.2.3.4/foo, has_password=false, has_username=false)"),
            ("http://1.2.3.4:81/foo", "http://1.2.3.4:81/foo", "SanitizedUrl(http://1.2.3.4:81/foo, has_password=false, has_username=false)"),
            ("fedimint://1.2.3.4:1000/foo", "fedimint://1.2.3.4:1000/foo", "SanitizedUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=false)"),
            ("fedimint://foo:bar@domain.com:1000/foo", "fedimint://domain.com:1000/foo", "SanitizedUrl(fedimint://domain.com:1000/foo, has_password=true, has_username=true)"),
            ("fedimint://foo@1.2.3.4:1000/foo", "fedimint://1.2.3.4:1000/foo", "SanitizedUrl(fedimint://1.2.3.4:1000/foo, has_password=false, has_username=true)"),
        ];

        for (url_str, sanitized_display_expected, sanitized_debug_expected) in test_cases {
            let url = Url::parse(url_str).unwrap();
            let sanitized_url = SanitizedUrl::new_borrowed(&url);

            let sanitized_display = format!("{sanitized_url}");
            assert_eq!(
                sanitized_display, sanitized_display_expected,
                "Display implementation out of spec"
            );

            let sanitized_debug = format!("{sanitized_url:?}");
            assert_eq!(
                sanitized_debug, sanitized_debug_expected,
                "Debug implementation out of spec"
            );
        }
    }
}

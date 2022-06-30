use bytes::Bytes;
use http_body::{Body as _, Full};

pub type Body = Full<Bytes>;
pub use http::*;

pub struct Response(pub http::Response<Full<Bytes>>);
impl Response {
    pub fn json<T: serde::Serialize>(value: &T) -> serde_json::Result<Self> {
        let bytes = serde_json::to_vec(value)?;
        let body = Full::new(Bytes::from(bytes));
        Ok(Self(http::Response::new(body)))
    }

    // read body as json, returns None if body was already read
    pub fn body_json<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Option<serde_json::Result<T>> {
        // this doesn't block because full data is available instantly
        let bytes = match futures::executor::block_on(self.0.body_mut().data()) {
            Some(Ok(body)) => body,
            None => return None,
            Some(Err(infailable)) => match infailable {},
        };

        Some(serde_json::from_slice(&bytes))
    }
}

impl From<StatusCode> for Response {
    fn from(code: StatusCode) -> Self {
        // empty body
        let body = Full::new(Bytes::new());
        let mut resp = http::Response::new(body);
        *resp.status_mut() = code;
        Self(resp)
    }
}


#[cfg(not(target_family = "wasm"))]
pub use std::time::SystemTime;

#[cfg(target_family = "wasm")]
pub use wasm::SystemTime;

#[cfg(target_family = "wasm")]
mod wasm {
    use std::ops::Add;
    use std::time::Duration;

    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};

    use crate::encoding::{Decodable, Encodable};

    #[derive(
        Debug,
        Eq,
        PartialEq,
        Hash,
        Clone,
        Ord,
        PartialOrd,
        Serialize,
        Deserialize,
        Encodable,
        Decodable,
    )]
    pub struct SystemTime(std::time::SystemTime);

    impl SystemTime {
        pub const UNIX_EPOCH: SystemTime = SystemTime(std::time::SystemTime::UNIX_EPOCH);

        pub fn now() -> SystemTime {
            SystemTime(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs_f64(js_sys::Date::new_0().get_time() / 1000.),
            )
        }

        pub fn duration_since(&self, earlier: SystemTime) -> anyhow::Result<Duration> {
            self.0
                .duration_since(earlier.0)
                .map_err(|_| anyhow!("Earlier time larger than self"))
        }
    }

    impl Add<Duration> for SystemTime {
        type Output = SystemTime;

        fn add(self, rhs: Duration) -> Self::Output {
            SystemTime(self.0 + rhs)
        }
    }
}

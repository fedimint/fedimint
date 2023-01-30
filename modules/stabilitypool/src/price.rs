use std::{
    fs::File,
    io::Read,
    sync::atomic::{self, AtomicU32, AtomicU64},
};

use anyhow::Result;
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::config::EpochConfig;

/// Oracle Client that returns prices in cents/BTC
#[async_trait]
pub trait OracleClient: Sync + Send + core::fmt::Debug {
    async fn price_at_epoch_start(
        &self,
        config: &EpochConfig,
        epoch_id: u64,
    ) -> anyhow::Result<u64> {
        let epoch_time =
            config.start_epoch_at() + Duration::new((epoch_id * config.epoch_length) as _, 0);
        self.price_at_time(epoch_time).await
    }

    async fn price_at_time(&self, datetime: OffsetDateTime) -> Result<u64>;

    async fn price_now(&self) -> Result<u64> {
        self.price_at_time(OffsetDateTime::now_utc()).await
    }
}

#[derive(Debug)]
pub struct MockOracle {
    pub url: reqwest::Url,
}

#[async_trait]
impl OracleClient for MockOracle {
    async fn price_at_time(&self, _datetime: OffsetDateTime) -> Result<u64> {
        #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
        struct Response {
            price: f32,
        }
        let price_at_time = reqwest::get(self.url.clone())
            .await?
            .json::<Response>()
            .await?
            .price;
        Ok((price_at_time * 100.0).floor() as u64)
    }
}

#[derive(Debug)]
pub struct FileOracle {
    pub path: std::path::PathBuf,
}

#[async_trait]
impl OracleClient for FileOracle {
    async fn price_at_time(&self, _datetime: OffsetDateTime) -> Result<u64> {
        let price = match File::open(&self.path.to_path_buf()) {
            Ok(mut f) => {
                let mut buf = String::new();
                f.read_to_string(&mut buf)?;
                buf.trim().parse::<f64>()?
            }
            // default price of $10,000 (or 1,000,000 cents) if file does not exist
            Err(_) => 1_000_000_f64,
        };
        Ok((price * 100.0).floor() as u64)
    }
}

#[derive(Debug)]
pub struct BitMexOracle {}

#[async_trait]
impl OracleClient for BitMexOracle {
    async fn price_at_time(&self, datetime: OffsetDateTime) -> Result<u64> {
        let mut url =
            reqwest::Url::parse("https://www.bitmex.com/api/v1/instrument/compositeIndex").unwrap();
        let symbol = ".BXBT";
        #[derive(serde::Serialize)]
        struct Filter<'a> {
            symbol: &'a str,
            #[serde(rename = "timestamp.hh")]
            timestamp_hour: u8,
            #[serde(rename = "timestamp.uu")]
            timestamp_min: u8,
            #[serde(rename = "timestamp.date")]
            timestamp_date: time::Date,
            #[serde(rename = "timestamp.ss")]
            timestamp_second: u8,
        }

        #[derive(serde::Deserialize, Debug, Clone, Copy)]
        #[serde(rename_all = "camelCase")]
        struct Price {
            last_price: f64,
        }
        let filter = serde_json::to_string(&Filter {
            timestamp_date: datetime.date(),
            timestamp_hour: datetime.hour(),
            timestamp_min: datetime.minute(),
            timestamp_second: 0,
            symbol,
        })
        .expect("serializes correctly");
        url.query_pairs_mut()
            .append_pair("symbol", symbol) // only interested in index
            .append_pair("filter", &filter)
            .append_pair("columns", "lastPrice,timestamp"); // only necessary fields

        let price_at_time = reqwest::get(url).await?.json::<[Price; 1]>().await?[0];

        Ok((price_at_time.last_price * 100.0).floor() as u64)
    }
}

#[derive(Debug)]
pub struct BackOff {
    /// Max delay in seconds
    pub max_delay: u64,
    pub base: u64,

    failures: AtomicU32,
    last_failure: AtomicU64,
}

impl BackOff {
    pub fn record_failure(&self, failure_time: OffsetDateTime) {
        let timestamp = failure_time.unix_timestamp() as u64;
        self.last_failure.swap(timestamp, atomic::Ordering::Relaxed);
        self.failures.fetch_add(1, atomic::Ordering::Relaxed);
    }

    pub fn reset(&self) -> u32 {
        self.failures.swap(0, atomic::Ordering::Relaxed)
    }

    pub fn can_retry(&self, now: OffsetDateTime) -> bool {
        now >= self.earliest_retry()
    }

    fn delay(&self) -> Duration {
        let failures = self.failures.load(atomic::Ordering::Relaxed);
        let delay = self.base.pow(failures).min(self.max_delay);
        Duration::new(delay as _, 0)
    }

    fn earliest_retry(&self) -> OffsetDateTime {
        let last_failure = OffsetDateTime::from_unix_timestamp(
            self.last_failure.load(atomic::Ordering::Relaxed) as _,
        )
        .expect("should be in range");
        last_failure + self.delay()
    }
}

impl Default for BackOff {
    fn default() -> Self {
        Self {
            max_delay: 20,
            base: 2,
            failures: AtomicU32::new(0),
            last_failure: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod test {
    use time::OffsetDateTime;

    use crate::BitMexOracle;
    use crate::OracleClient;

    #[tokio::test]
    async fn get_price_at_time() {
        use time::format_description::well_known::Rfc3339;
        let time = OffsetDateTime::parse("2023-01-17T00:00:00.000Z", &Rfc3339).unwrap();
        let client = BitMexOracle {};
        assert_eq!(client.price_at_time(time).await.unwrap(), 2118721);
    }
}

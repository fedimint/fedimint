use std::collections::BTreeMap;
use std::io::Write;

use super::{DataDir, dto};

#[test]
fn state_roundtrip_and_replacement() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("fm-portalloc.json");
    let mut data_dir = DataDir::new(dir.path())?;
    data_dir.with_lock(|locked| {
        assert_eq!(
            serde_json::to_value(locked.load_data()?)?,
            serde_json::to_value(dto::RootData::default())?
        );
        // Exceed the I/O buffers without probing or reserving real ports.
        let keys: BTreeMap<_, _> = (10000..12000)
            .map(|port| (port, serde_json::json!({"size": 1, "expires": u64::MAX})))
            .collect();
        let value = serde_json::json!({"next": 12000, "keys": keys});
        let data: dto::RootData = serde_json::from_value(value.clone())?;
        locked.store_data(&data)?;
        assert_eq!(serde_json::to_value(locked.load_data()?)?, value);
        assert_eq!(std::fs::read(&path)?, serde_json::to_vec_pretty(&data)?);
        assert!(std::fs::metadata(&path)?.len() > 8192);
        assert!(!path.with_extension("tmp").exists());

        let data = dto::RootData::default();
        locked.store_data(&data)?;
        assert_eq!(
            serde_json::to_value(locked.load_data()?)?,
            serde_json::to_value(&data)?
        );
        assert_eq!(std::fs::read(&path)?, serde_json::to_vec_pretty(&data)?);
        assert!(!path.with_extension("tmp").exists());
        Ok(())
    })
}

#[test]
fn malformed_state_is_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut data_dir = DataDir::new(dir.path())?;
    std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(dir.path().join("fm-portalloc.json"))?
        .write_all(b"{")?;
    data_dir.with_lock(|locked| {
        assert!(locked.load_data().is_err());
        Ok(())
    })
}

use std::io;

use super::{store_json_pretty_to_file, store_to_file_with};

#[test]
fn failed_write_preserves_destination() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("data.json");
    store_json_pretty_to_file(&path, &vec![1, 2, 3])?;
    let original = std::fs::read(&path)?;
    let result = store_to_file_with(&path, |writer| -> io::Result<()> {
        writer.write_all(b"partial")?;
        Err(io::Error::other("injected serialization failure"))
    })?;
    assert!(result.is_err());
    assert_eq!(std::fs::read(&path)?, original);
    store_json_pretty_to_file(&path, &vec![4])?;
    assert_eq!(std::fs::read(&path)?, serde_json::to_vec_pretty(&vec![4])?);
    Ok(())
}

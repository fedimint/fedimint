pub mod db;
pub mod envs;

use std::path::PathBuf;
use std::{env, fs};

use envs::FM_TEST_DIR_ENV;
use tempfile::TempDir;

/// If `FM_TEST_DIR` is set, use it as a base, otherwise use a tempdir
///
/// Callers must hold onto the tempdir until it is no longer needed
pub fn test_dir(pathname: &str) -> (PathBuf, Option<TempDir>) {
    let (parent, maybe_tmp_dir_guard) = if let Ok(directory) = env::var(FM_TEST_DIR_ENV) {
        (directory, None)
    } else {
        let random = format!("test-{}", rand::random::<u64>());
        let guard = tempfile::Builder::new().prefix(&random).tempdir().unwrap();
        let directory = guard.path().to_str().unwrap().to_owned();
        (directory, Some(guard))
    };
    let fullpath = PathBuf::from(parent).join(pathname);
    fs::create_dir_all(fullpath.clone()).expect("Can make dirs");
    (fullpath, maybe_tmp_dir_guard)
}

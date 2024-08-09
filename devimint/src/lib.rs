#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::explicit_deref_methods)]
#![allow(clippy::implicit_hasher)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::large_futures)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]

use std::ffi;

use clap::Parser as _;
use cli::cleanup_on_exit;
use devfed::DevJitFed;
pub use devfed::{dev_fed, DevFed};
pub use external::{
    external_daemons, ExternalDaemons, LightningNode, Lightningd, LightningdProcessHandle, Lnd,
};
use futures::Future;
pub use gatewayd::Gatewayd;
use tests::log_binary_versions;
use util::ProcessManager;

pub mod cli;
pub mod devfed;
pub mod envs;
pub mod external;
pub mod federation;
pub mod gatewayd;
pub mod tests;
pub mod util;
pub mod vars;
pub mod version_constants;

pub async fn run_devfed_test<F, FF>(f: F) -> anyhow::Result<()>
where
    F: FnOnce(DevJitFed, ProcessManager) -> FF,
    FF: Future<Output = anyhow::Result<()>>,
{
    let args = cli::CommonArgs::parse_from::<_, ffi::OsString>(vec![]);

    let (process_mgr, task_group) = cli::setup(args).await?;
    log_binary_versions().await?;
    let dev_fed = devfed::DevJitFed::new(&process_mgr, false)?;
    // workaround https://github.com/tokio-rs/tokio/issues/6463
    // by waiting on all jits to complete, we make it less likely
    // that something is not finished yet and will block in `on_block`
    let _ = dev_fed.finalize(&process_mgr).await;
    let res = cleanup_on_exit(f(dev_fed.clone(), process_mgr.clone()), task_group).await;
    dev_fed.fast_terminate().await;
    res?;

    Ok(())
}

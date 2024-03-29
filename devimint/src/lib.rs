use std::ffi;

use clap::Parser as _;
use cli::cleanup_on_exit;
use devfed::DevJitFed;
pub use devfed::{dev_fed, DevFed};
pub use external::{
    external_daemons, open_channel, ExternalDaemons, LightningNode, Lightningd,
    LightningdProcessHandle, Lnd,
};
use futures::Future;
pub use gatewayd::Gatewayd;
use tests::log_binary_versions;

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
    F: FnOnce(DevJitFed) -> FF,
    FF: Future<Output = anyhow::Result<()>>,
{
    let args = cli::CommonArgs::parse_from::<_, ffi::OsString>(vec![]);

    let (process_mgr, task_group) = cli::setup(args).await?;
    log_binary_versions().await?;
    let dev_fed = devfed::DevJitFed::new(&process_mgr)?;
    let res = cleanup_on_exit(f(dev_fed.clone()), task_group).await;
    // workaround https://github.com/tokio-rs/tokio/issues/6463
    // by waiting on all jits to complete, we make it less likely
    // that something is not finished yet and will block in `on_block`
    let _ = dev_fed.finalize(&process_mgr).await;
    res
}

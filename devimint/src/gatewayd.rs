use std::collections::HashMap;
use std::ops::ControlFlow;

use anyhow::{Context, Result};
use ln_gateway::rpc::V1_API_ENDPOINT;

use crate::cmd;
use crate::external::LightningNode;
use crate::federation::Federation;
use crate::util::{poll, Command, ProcessHandle, ProcessManager};
use crate::vars::utf8;

#[derive(Clone)]
pub struct Gatewayd {
    pub(crate) _process: ProcessHandle,
    pub ln: Option<LightningNode>,
    pub(crate) addr: String,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: LightningNode) -> Result<Self> {
        let ln_name = ln.name();
        let test_dir = &process_mgr.globals.FM_TEST_DIR;
        let port = match ln {
            LightningNode::Cln(_) => process_mgr.globals.FM_PORT_GW_CLN,
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_GW_LND,
        };
        let addr = format!("http://127.0.0.1:{port}/{V1_API_ENDPOINT}");
        let gateway_env: HashMap<String, String> = HashMap::from_iter([
            (
                "FM_GATEWAY_DATA_DIR".to_owned(),
                format!("{}/{ln_name}", utf8(test_dir)),
            ),
            (
                "FM_GATEWAY_LISTEN_ADDR".to_owned(),
                format!("127.0.0.1:{port}"),
            ),
            ("FM_GATEWAY_API_ADDR".to_owned(), addr.clone()),
        ]);
        let process = process_mgr
            .spawn_daemon(
                &format!("gatewayd-{ln_name}"),
                cmd!(crate::util::Gatewayd, ln_name).envs(gateway_env),
            )
            .await?;

        Ok(Self {
            ln: Some(ln),
            _process: process,
            addr,
        })
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = Some(ln_node);
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        tracing::info!("Stopping lightning node");
        match self.ln.take() {
            Some(LightningNode::Lnd(lnd)) => lnd.terminate().await,
            Some(LightningNode::Cln(cln)) => cln.terminate().await,
            None => Err(anyhow::anyhow!(
                "Cannot stop an already stopped Lightning Node"
            )),
        }
    }

    pub async fn cmd(&self) -> Command {
        cmd!(
            crate::util::get_gateway_cli_path(),
            "--rpcpassword=theresnosecondbest",
            "-a",
            &self.addr
        )
    }

    pub async fn gateway_id(&self) -> Result<String> {
        let info = cmd!(self, "info").out_json().await?;
        let gateway_id = info["gateway_id"]
            .as_str()
            .context("gateway_id must be a string")?
            .to_owned();
        Ok(gateway_id)
    }

    pub async fn connect_fed(&self, fed: &Federation) -> Result<()> {
        let invite_code = fed.invite_code()?;
        poll("gateway connect-fed", 60, || async {
            cmd!(self, "connect-fed", invite_code.clone())
                .run()
                .await
                .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await?;
        Ok(())
    }
}

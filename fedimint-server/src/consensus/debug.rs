use std::fmt;

use bitcoin::hashes::{sha256, Hash as _};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::session_outcome::AcceptedItem;

use crate::ConsensusItem;

/// A newtype for a nice [`fmt::Debug`] of a [`ConsensusItem`]
pub struct DebugConsensusItem<'ci>(pub &'ci ConsensusItem);

impl<'ci> fmt::Debug for DebugConsensusItem<'ci> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ConsensusItem::Module(mci) => {
                f.write_fmt(format_args!(
                    "Module CI: module={} ci={}",
                    mci.module_instance_id(),
                    mci
                ))?;
            }
            ConsensusItem::Transaction(tx) => {
                f.write_fmt(format_args!(
                    "Transaction txid={}, inputs_num={}, outputs_num={}",
                    tx.tx_hash(),
                    tx.inputs.len(),
                    tx.outputs.len(),
                ))?;
                // TODO: This is kind of lengthy, and maybe could be conditionally enabled
                // via an env var or something.
                for input in &tx.inputs {
                    // TODO: add pretty print fn to interface
                    f.write_fmt(format_args!("\n    Input: {input}"))?;
                }
                for output in &tx.outputs {
                    f.write_fmt(format_args!("\n    Output: {output}")).unwrap();
                }
            }
            ConsensusItem::Default { variant, .. } => {
                f.write_fmt(format_args!("Unknown CI variant: {variant}"))?;
            }
        }
        Ok(())
    }
}

/// A compact citem formatter, useful for debugging in case of consensus failure
///
/// Unlike [`DebugConsensusItem`], this one is used when a (potentially) long
/// list of citems are dumped, so it needs to be very compact.
pub struct DebugConsensusItemCompact<'a>(pub &'a AcceptedItem);

impl<'a> fmt::Display for DebugConsensusItemCompact<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut engine = sha256::HashEngine::default();
        let len = self
            .0
            .consensus_encode(&mut engine)
            .map_err(|_| fmt::Error)?;
        let hash = *sha256::Hash::from_engine(engine).as_byte_array();
        f.write_fmt(format_args!(
            "{}; peer={}; len={}; ",
            hex::encode(&hash[0..12]),
            self.0.peer,
            len
        ))?;

        match &self.0.item {
            ConsensusItem::Transaction(ref tx) => {
                f.write_fmt(format_args!("txid={}; ", tx.tx_hash()))?;
                f.write_str("inputs_module_ids=")?;
                for (i, input) in tx.inputs.iter().enumerate() {
                    if i != 0 {
                        f.write_str(",")?;
                    }
                    f.write_fmt(format_args!("{}", input.module_instance_id()))?;
                }
                f.write_str("; outputs_module_ids=")?;
                for (i, output) in tx.outputs.iter().enumerate() {
                    if i != 0 {
                        f.write_str(",")?;
                    }
                    f.write_fmt(format_args!("{}", output.module_instance_id()))?;
                }
            }
            ConsensusItem::Module(module_citem) => {
                f.write_fmt(format_args!(
                    "citem={}; ",
                    module_citem.module_instance_id()
                ))?;
            }
            ConsensusItem::Default { variant, .. } => {
                f.write_fmt(format_args!("unknown variant={variant}"))?;
            }
        }

        Ok(())
    }
}

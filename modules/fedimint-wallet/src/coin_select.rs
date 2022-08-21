use std::collections::BTreeSet;

use bitcoin::{Transaction, TxOut};

const TXIN_BASE_WEIGHT: u32 = (32 + 4 + 4) * 4;

#[derive(Debug, Clone)]
pub struct CoinSelector {
    candidates: Vec<WeightedValue>,
    selected: BTreeSet<usize>,
    opts: CoinSelectorOpt,
}

#[derive(Debug, Clone, Copy)]
pub struct WeightedValue {
    pub value: u64,
    pub satisfaction_weight: u32,
    pub is_segwit: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CoinSelectorOpt {
    /// The value we need to select.
    /// TODO: This should be an option as sometimes we want to spend everything.
    pub target_value: u64,
    /// The feerate we should try and achieve in sats per weight unit.
    pub target_feerate: f32,
    /// The minimum absolute fee.
    pub min_absolute_fee: u64,
    /// The weight of the template transaction including fixed inputs and outputs.
    pub base_weight: u32,
    /// The weight of the drain (change) output.
    pub drain_weight: u32,
    /// The input value of the template transaction.
    pub starting_input_value: u64,
}

impl CoinSelectorOpt {
    /// Create [`CoinSelectorOpt`] with default values.
    ///
    /// `base_weight`: Weight of tx with fixed inputs and fixed outputs
    /// `drain_weight`: Weight of the drain output
    pub fn from_weights(base_weight: u32, drain_weight: u32) -> Self {
        Self {
            target_value: 0,
            // 0.25 per wu i.e. 1 sat per byte
            target_feerate: 0.25,
            min_absolute_fee: 0,
            base_weight,
            drain_weight,
            starting_input_value: 0,
        }
    }

    pub fn fund_outputs(txouts: &[TxOut], drain_output: &TxOut) -> Self {
        let mut tx = Transaction {
            input: vec![],
            version: 1,
            lock_time: 0, // TODO: set to recent block height
            output: txouts.to_vec(),
        };
        let base_weight = tx.weight();
        // this awkward calculation is necessary since TxOut doesn't have \.weight()
        let drain_weight = {
            tx.output.push(drain_output.clone());
            tx.weight() - base_weight
        };
        Self {
            target_value: txouts.iter().map(|txout| txout.value).sum(),
            ..Self::from_weights(base_weight as u32, drain_weight as u32)
        }
    }
}

impl CoinSelector {
    pub fn _candidates(&self) -> &[WeightedValue] {
        &self.candidates
    }

    pub fn new(candidates: Vec<WeightedValue>, opts: CoinSelectorOpt) -> Self {
        Self {
            candidates,
            selected: Default::default(),
            opts,
        }
    }

    pub fn select(&mut self, index: usize) {
        assert!(index < self.candidates.len());
        self.selected.insert(index);
    }

    pub fn current_weight(&self) -> u32 {
        let witness_header_extra_weight = self
            .selected()
            .find(|(_, wv)| wv.is_segwit)
            .map(|_| 2)
            .unwrap_or(0);
        self.opts.base_weight
            + self
                .selected()
                .map(|(_, wv)| wv.satisfaction_weight + TXIN_BASE_WEIGHT)
                .sum::<u32>()
            + witness_header_extra_weight
    }

    pub fn selected(&self) -> impl Iterator<Item = (usize, WeightedValue)> + '_ {
        self.selected
            .iter()
            .map(move |index| (*index, *self.candidates.get(*index).unwrap()))
    }

    pub fn unselected(&self) -> Vec<usize> {
        let all_indexes = (0..self.candidates.len()).collect::<BTreeSet<_>>();
        all_indexes.difference(&self.selected).cloned().collect()
    }

    pub fn _all_selected(&self) -> bool {
        self.selected.len() == self.candidates.len()
    }

    pub fn _select_all(&mut self) {
        for next_unselected in self.unselected() {
            self.select(next_unselected)
        }
    }

    pub fn select_until_finished(&mut self) -> Result<Selection, SelectionFailure> {
        let mut selection = self.finish();

        if selection.is_ok() {
            return selection;
        }

        for next_unselected in self.unselected() {
            self.select(next_unselected);
            selection = self.finish();

            if selection.is_ok() {
                break;
            }
        }

        selection
    }

    pub fn current_value(&self) -> u64 {
        self.opts.starting_input_value + self.selected().map(|(_, wv)| wv.value).sum::<u64>()
    }

    pub fn finish(&self) -> Result<Selection, SelectionFailure> {
        let base_weight = self.current_weight();

        if self.current_value() < self.opts.target_value {
            return Err(SelectionFailure::InsufficientFunds {
                selected: self.current_value(),
                needed: self.opts.target_value,
            });
        }

        let inputs_minus_outputs = self.current_value() - self.opts.target_value;

        // check fee rate satisfied
        let feerate_without_drain = inputs_minus_outputs as f32 / base_weight as f32;

        // we simply don't have enough fee to acheieve the feerate
        if feerate_without_drain < self.opts.target_feerate {
            return Err(SelectionFailure::FeerateTooLow {
                needed: self.opts.target_feerate,
                had: feerate_without_drain,
            });
        }

        if inputs_minus_outputs < self.opts.min_absolute_fee {
            return Err(SelectionFailure::AbsoluteFeeTooLow {
                needed: self.opts.min_absolute_fee,
                had: inputs_minus_outputs,
            });
        }

        let weight_with_drain = base_weight + self.opts.drain_weight;
        let target_fee_with_drain = ((self.opts.target_feerate * weight_with_drain as f32).ceil()
            as u64)
            .max(self.opts.min_absolute_fee);
        let target_fee_without_drain = ((self.opts.target_feerate * base_weight as f32).ceil()
            as u64)
            .max(self.opts.min_absolute_fee);

        let (excess, use_drain) = match inputs_minus_outputs.checked_sub(target_fee_with_drain) {
            Some(excess) => (excess, true),
            None => {
                let implied_output_value = self.current_value() - target_fee_without_drain;
                match implied_output_value.checked_sub(self.opts.target_value) {
                    Some(excess) => (excess, false),
                    None => {
                        return Err(SelectionFailure::InsufficientFunds {
                            selected: self.current_value(),
                            needed: target_fee_without_drain + self.opts.target_value,
                        })
                    }
                }
            }
        };

        let (total_weight, fee) = if use_drain {
            (weight_with_drain, target_fee_with_drain)
        } else {
            (base_weight, target_fee_without_drain)
        };

        Ok(Selection {
            selected: self.selected.clone(),
            excess,
            use_drain,
            total_weight,
            fee,
        })
    }
}

#[derive(Clone, Debug)]
pub enum SelectionFailure {
    InsufficientFunds { selected: u64, needed: u64 },
    FeerateTooLow { needed: f32, had: f32 },
    AbsoluteFeeTooLow { needed: u64, had: u64 },
}

impl core::fmt::Display for SelectionFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SelectionFailure::InsufficientFunds { selected, needed } => write!(
                f,
                "insufficient coins selected, had {} needed {}",
                selected, needed
            ),
            SelectionFailure::FeerateTooLow { needed, had } => {
                write!(f, "feerate too low, needed {}, had {}", needed, had)
            }
            SelectionFailure::AbsoluteFeeTooLow { needed, had } => {
                write!(f, "absolute fee too low, needed {}, had {}", needed, had)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SelectionFailure {}

#[derive(Clone, Debug)]
pub struct Selection {
    pub selected: BTreeSet<usize>,
    pub excess: u64,
    pub fee: u64,
    pub use_drain: bool,
    pub total_weight: u32,
}

impl Selection {
    pub fn filter_selected<'a, T>(
        &'a self,
        candidates: &'a [T],
    ) -> impl Iterator<Item = &'a T> + 'a {
        self.selected.iter().map(move |i| &candidates[*i])
    }
}

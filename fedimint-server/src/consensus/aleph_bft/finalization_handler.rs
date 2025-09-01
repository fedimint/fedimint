use aleph_bft::{NodeIndex, Round};
use fedimint_core::PeerId;
use tokio::sync::watch;

use super::data_provider::UnitData;

pub struct OrderedUnit {
    pub creator: PeerId,
    pub round: Round,
    pub data: Option<UnitData>,
}

pub struct FinalizationHandler {
    sender: async_channel::Sender<OrderedUnit>,
    unit_count_sender: watch::Sender<usize>,
}

impl FinalizationHandler {
    pub fn new(
        sender: async_channel::Sender<OrderedUnit>,
        unit_count_sender: watch::Sender<usize>,
    ) -> Self {
        Self {
            sender,
            unit_count_sender,
        }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, _data: UnitData) {
        unreachable!("This method is not called")
    }

    fn unit_finalized(&mut self, creator: NodeIndex, round: Round, data: Option<UnitData>) {
        self.unit_count_sender.send_modify(|count| *count += 1);
        // the channel is unbounded
        self.sender
            .try_send(OrderedUnit {
                creator: super::to_peer_id(creator),
                round,
                data,
            })
            .ok();
    }
}

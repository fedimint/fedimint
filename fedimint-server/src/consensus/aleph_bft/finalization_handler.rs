use aleph_bft::{NodeIndex, Round};
use fedimint_core::PeerId;

use super::data_provider::UnitData;

pub struct OrderedUnit {
    pub creator: PeerId,
    pub round: Round,
    pub data: Option<UnitData>,
}

pub struct FinalizationHandler {
    sender: async_channel::Sender<OrderedUnit>,
}

impl FinalizationHandler {
    pub fn new(sender: async_channel::Sender<OrderedUnit>) -> Self {
        Self { sender }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, _data: UnitData) {
        unreachable!("This method is not called")
    }

    fn unit_finalized(&mut self, creator: NodeIndex, round: Round, data: Option<UnitData>) {
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

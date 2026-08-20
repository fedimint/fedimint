use aleph_bft::{NodeIndex, Round};
use fedimint_core::PeerId;

use super::data_provider::UnitData;
use super::idle::IdleCoordinator;

pub struct OrderedUnit {
    pub creator: PeerId,
    pub round: Round,
    pub data: Option<UnitData>,
}

pub struct FinalizationHandler {
    sender: async_channel::Sender<OrderedUnit>,
    idle: IdleCoordinator,
}

impl FinalizationHandler {
    pub fn new(sender: async_channel::Sender<OrderedUnit>, idle: IdleCoordinator) -> Self {
        Self { sender, idle }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, _data: UnitData) {
        unreachable!("This method is not called")
    }

    fn unit_finalized(&mut self, creator: NodeIndex, round: Round, data: Option<UnitData>) {
        if super::to_peer_id(creator) == Some(self.idle.identity())
            && let Some(data) = &data
        {
            self.idle.batch_finalized(data);
        }
        // the channel is unbounded
        self.sender
            .try_send(OrderedUnit {
                // Skipping a finalized unit would make us compute a different session
                // outcome than our peers, so we must not swallow an invalid index here.
                // It is unreachable regardless: a unit is only finalized after its
                // signature was verified against our broadcast public key set, which
                // requires its creator to be one of our peers.
                creator: super::to_peer_id(creator)
                    .expect("Finalized units were verified against the broadcast public key set"),
                round,
                data,
            })
            .ok();
    }
}

use aleph_bft::{NodeIndex, Round};
use fedimint_core::PeerId;

use super::data_provider::{UnitData, UnorderedBatches};

pub struct OrderedUnit {
    pub creator: PeerId,
    pub round: Round,
    pub data: Option<UnitData>,
}

pub struct FinalizationHandler {
    sender: async_channel::Sender<OrderedUnit>,
    identity: PeerId,
    unordered_batches: UnorderedBatches,
}

impl FinalizationHandler {
    pub fn new(
        sender: async_channel::Sender<OrderedUnit>,
        identity: PeerId,
        unordered_batches: UnorderedBatches,
    ) -> Self {
        Self {
            sender,
            identity,
            unordered_batches,
        }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, _data: UnitData) {
        unreachable!("This method is not called")
    }

    fn unit_finalized(&mut self, creator: NodeIndex, round: Round, data: Option<UnitData>) {
        // Skipping a finalized unit would make us compute a different session
        // outcome than our peers, so we must not swallow an invalid index here.
        // It is unreachable regardless: a unit is only finalized after its
        // signature was verified against our broadcast public key set, which
        // requires its creator to be one of our peers.
        let creator = super::to_peer_id(creator)
            .expect("Finalized units were verified against the broadcast public key set");

        // the data provider stops creating units as soon as all of our batches have
        // been ordered
        if creator == self.identity && matches!(data, Some(UnitData::Batch(..))) {
            self.unordered_batches.ordered();
        }

        // the channel is unbounded
        self.sender
            .try_send(OrderedUnit {
                creator,
                round,
                data,
            })
            .ok();
    }
}

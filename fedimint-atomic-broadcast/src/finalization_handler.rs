use crate::data_provider::UnitData;

pub struct FinalizationHandler {
    sender: async_channel::Sender<UnitData>,
}

impl FinalizationHandler {
    pub fn new(sender: async_channel::Sender<UnitData>) -> Self {
        Self { sender }
    }
}

impl aleph_bft::FinalizationHandler<UnitData> for FinalizationHandler {
    fn data_finalized(&mut self, unit_data: UnitData) {
        // the channel is unbounded - dropping unit data does not risk inconsistent
        // state
        self.sender.try_send(unit_data).ok();
    }
}

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::{debug, trace};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MessageQueue<M> {
    pub(super) queue: VecDeque<UniqueMessage<M>>,
    pub(super) next_id: MessageId,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct MessageId(pub u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct UniqueMessage<M> {
    pub id: MessageId,
    pub msg: M,
}

impl MessageId {
    pub fn increment(self) -> MessageId {
        MessageId(self.0 + 1)
    }
}

impl<M> Default for MessageQueue<M> {
    fn default() -> Self {
        MessageQueue {
            queue: Default::default(),
            next_id: MessageId(1),
        }
    }
}

impl<M> MessageQueue<M>
where
    M: Clone,
{
    pub fn push(&mut self, msg: M) -> UniqueMessage<M> {
        let id_msg = UniqueMessage {
            id: self.next_id,
            msg,
        };

        self.queue.push_back(id_msg.clone());
        self.next_id = self.next_id.increment();

        id_msg
    }

    pub fn ack(&mut self, msg_id: MessageId) {
        debug!("Received ACK for {:?}", msg_id);
        while self
            .queue
            .front()
            .map(|msg| msg.id <= msg_id)
            .unwrap_or(false)
        {
            let msg = self.queue.pop_front().expect("Checked in while head");
            trace!("Removing message {:?} from resend buffer", msg.id);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &UniqueMessage<M>> {
        self.queue.iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::net::queue::{MessageId, MessageQueue};

    #[test]
    fn test_queue() {
        let mut queue = MessageQueue::default();

        for i in 0u64..10 {
            let umsg = queue.push(42 * i);
            assert_eq!(umsg.msg, 42 * i);
            assert_eq!(umsg.id.0, i + 1);
        }

        fn assert_contains(queue: &MessageQueue<u64>, iter: impl Iterator<Item = u64>) {
            let mut queue_iter = queue.iter();

            for i in iter {
                let umsg = queue_iter.next().unwrap();
                assert_eq!(umsg.msg, 42 * i);
                assert_eq!(umsg.id.0, i + 1);
            }

            assert_eq!(queue_iter.next(), None);
        }

        assert_eq!(queue.iter().count(), 10);
        assert_contains(&queue, 0..10);

        queue.ack(MessageId(1));
        assert_contains(&queue, 1..10);

        queue.ack(MessageId(4));
        assert_contains(&queue, 4..10);

        queue.ack(MessageId(2)); // TODO: should that throw an error?
        assert_contains(&queue, 4..10);
    }
}

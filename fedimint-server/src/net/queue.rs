use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::MaybeEpochMessage;

/// Message queue to manage unsent and unacknowledged messages
///
/// # Lifetime of a message
/// 1. A message is inserted into the queue using `queue_message`. It receives an auto-incrementing
///    message id.
/// 2. Unsent messages are retrieved using `next_send_message`.
/// 3. If sending a message succeeds `mark_sent` is called after which the next call to
///    `next_send_message` will return the next message to be sent. The message remains in the
///    buffer though till an ACK is received.
///
///    The separation of step 2+3 is necessary to make the future that attempts to send the message
///    cancellation safe. Marking the message as sent has to happen right after the future writing
///    it to the destination returns, without an await point in between.
/// 4. Once an acknowledgement is received for a message, `ack` is called with its message id. All
///    messages with a lower or equal id will be removed from the buffer.
/// 5. If a reconnect happens all messages that have not been acknowledged have to be resent. In
///    that case `resend_all` has to be called.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MessageQueue<M> {
    /// Messages that were scheduled to be sent (sent and unsent) and not acknowledged yet
    pub(super) queue: VecDeque<UniqueMessage<M>>,
    /// Id for the next message to be inserted into the queue
    next_id: MessageId,
    /// How many of the messages at the tip of the queue weren't sent out yet
    unsent_messages: u64,
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
            unsent_messages: 0,
        }
    }
}

impl<M> MessageQueue<M>
where
    M: Clone,
{
    /// Queue message for being sent over the wire
    pub fn queue_message(&mut self, msg: M) {
        self.queue.push_back(UniqueMessage {
            id: self.next_id,
            msg,
        });
        trace!(id = ?self.next_id, "Queueing outgoing message");
        self.next_id = self.next_id.increment();
        self.unsent_messages += 1;
    }

    /// Remove all messages older than `msg_id` from the buffer since they were received by our peer
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

        // If we got an ACK from the future we remove all of them from the queue even if we haven't
        // sent them yet (can happen on reconnect). In that case we need to adjust the unsent
        // messages field so we never try to send messages not in the buffer anymore
        let queued_messages = self.queue.len() as u64;
        if self.unsent_messages > queued_messages {
            self.unsent_messages = queued_messages;
        }
    }

    /// Fetch the next message to be sent from the queue
    pub fn next_send_message(&self) -> Option<&UniqueMessage<M>> {
        if self.unsent_messages > 0 {
            let idx = self.queue.len() - (self.unsent_messages as usize);
            // If we always properly update unsent_messages this can never fail
            let maybe_message = self
                .queue
                .get(idx)
                .expect("We tried to send a message no longer in the buffer");

            Some(maybe_message)
        } else {
            None
        }
    }

    /// Marks the message `msg_id` as sent over the wire. This does not aknowledge the receipt by
    /// our peer and thus keeps the message in the buffer in case it needs to be re-sent.
    pub fn mark_sent(&mut self, msg_id: MessageId) {
        assert_ne!(self.unsent_messages, 0, "There are no messages to be sent!");
        assert_eq!(
            msg_id.0,
            self.next_id.0 - self.unsent_messages,
            "The sent message is not the expected one!"
        );
        self.unsent_messages -= 1;
    }

    /// Mark all messages as unsent to attempt re-sending and return the oldest and newest messages
    /// to be sent.
    pub fn resend_all(&mut self) -> Option<(MessageId, MessageId)> {
        self.unsent_messages = self.queue.len() as u64;

        if self.queue.is_empty() {
            None
        } else {
            let oldest = self.queue.front().expect("Queue not empty").id;
            let newest = self.queue.back().expect("Queue not empty").id;
            Some((oldest, newest))
        }
    }

    /// Return the number of unsent messages
    pub fn unsent_len(&self) -> usize {
        self.unsent_messages as usize
    }
}

impl<M: MaybeEpochMessage> MessageQueue<M> {
    /// Returns the number of epochs the buffer has messages of. This assumes that the we send
    /// messages in each epoch and the epoch only increases.
    pub fn buffered_epochs(&self) -> u64 {
        // We only have non-epoch messages during DKG and on re-joins. Both happen infrequently
        // enough that this O(n) search for the lowest and highest epoch number in the buffer is
        // sufficient
        let maybe_oldest = self.queue.iter().find_map(|msg| msg.msg.message_epoch());
        let maybe_newest = self
            .queue
            .iter()
            .rev()
            .find_map(|msg| msg.msg.message_epoch());
        match (maybe_oldest, maybe_newest) {
            (Some(oldest_epoch), Some(newest_epoch)) => {
                assert!(oldest_epoch <= newest_epoch);
                newest_epoch - oldest_epoch + 1
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::net::queue::{MessageId, MessageQueue, UniqueMessage};

    #[test]
    fn test_queue() {
        let mut queue = MessageQueue::default();

        // Test queuing unsent
        for i in 0u64..10 {
            queue.queue_message(42 * i);
            assert_eq!(queue.next_id, MessageId(i + 2));
            assert_eq!(queue.unsent_messages, i + 1);
            assert_eq!(
                queue.next_send_message().unwrap(),
                &UniqueMessage {
                    id: MessageId(1),
                    msg: 0
                }
            );
        }

        // Test sending
        queue.mark_sent(MessageId(1));
        assert_eq!(
            queue.next_send_message().unwrap(),
            &UniqueMessage {
                id: MessageId(2),
                msg: 42
            }
        );
        queue.mark_sent(MessageId(2));
        assert_eq!(
            queue.next_send_message().unwrap(),
            &UniqueMessage {
                id: MessageId(3),
                msg: 84
            }
        );

        // Test ACK
        queue.ack(MessageId(1));
        assert_eq!(queue.queue.len(), 9);

        // Test resend
        queue.resend_all();
        assert_eq!(
            queue.next_send_message().unwrap(),
            &UniqueMessage {
                id: MessageId(2),
                msg: 42
            }
        );
    }
}

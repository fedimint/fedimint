use std::fmt::Debug;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct ExchangePoint<A, B> {
    sender: Sender<A>,
    receiver: Receiver<B>,
}

impl<A, B> ExchangePoint<A, B>
where
    A: Debug,
    B: Debug,
{
    pub fn new() -> (ExchangePoint<A, B>, ExchangePoint<B, A>) {
        let (sender_a, receiver_b) = channel(1);
        let (sender_b, receiver_a) = channel(1);

        (
            ExchangePoint {
                sender: sender_a,
                receiver: receiver_a,
            },
            ExchangePoint {
                sender: sender_b,
                receiver: receiver_b,
            },
        )
    }

    pub async fn exchange(&mut self, a: A) -> B {
        self.sender.send(a).await.expect("other thread died (send)");
        self.receiver
            .recv()
            .await
            .expect("other thread died (receive)")
    }
}

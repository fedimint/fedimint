use std::iter::repeat;
use std::sync::Arc;

use bitcoin::Address;
use fedimint_api::config::ClientConfig;
use fedimint_api::{Amount, OutPoint};
use itertools::Itertools;
use mint_client::Client;

use crate::rng;

#[derive(Clone)]
pub struct UserTest<C> {
    pub client: Arc<Client<C>>,
    pub config: C,
}

impl<T: AsRef<ClientConfig> + Clone> UserTest<T> {
    pub fn new(client: Arc<Client<T>>) -> Self {
        let config = client.config();
        UserTest { client, config }
    }

    /// Helper to simplify the peg_out method calls
    pub async fn peg_out(&self, amount: u64, address: &Address) -> (Amount, OutPoint) {
        let peg_out = self
            .client
            .new_peg_out_with_fees(bitcoin::Amount::from_sat(amount), address.clone())
            .await
            .unwrap();
        let out_point = self.client.peg_out(peg_out.clone(), rng()).await.unwrap();
        (peg_out.fees.amount().into(), out_point)
    }

    /// Returns the amount denominations of all coins from lowest to highest
    pub async fn coin_amounts(&self) -> Vec<Amount> {
        self.client
            .coins()
            .await
            .iter_tiers()
            .flat_map(|(a, c)| repeat(*a).take(c.len()))
            .sorted()
            .collect::<Vec<Amount>>()
    }

    /// Returns sum total of all coins
    pub async fn total_coins(&self) -> Amount {
        self.client.coins().await.total_amount()
    }

    pub async fn assert_total_coins(&self, amount: Amount) {
        self.client.fetch_all_coins().await;
        assert_eq!(self.total_coins().await, amount);
    }
    pub async fn assert_coin_amounts(&self, amounts: Vec<Amount>) {
        self.client.fetch_all_coins().await;
        assert_eq!(self.coin_amounts().await, amounts);
    }
}

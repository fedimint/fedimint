use serde::{Deserialize, Serialize};

pub mod payload {
    //TODO
}

pub mod responses {
    use crate::utils::CoinsByTier;
    use minimint_core::modules::mint::tiered::coins::Coins;
    use mint_client::mint::SpendableCoin;
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct InfoResponse {
        coins: Vec<CoinsByTier>,
    }

    impl InfoResponse {
        pub fn build(coins: Coins<SpendableCoin>) -> Self {
            let info_coins: Vec<CoinsByTier> = coins
                .coins
                .iter()
                .map(|(tier, c)| super::CoinsByTier {
                    quantity: c.len(),
                    tier: tier.milli_sat,
                })
                .collect();
            Self { coins: info_coins }
        }
    }
}

// Holds quantity of coins per tier
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoinsByTier {
    tier: u64,
    quantity: usize,
}

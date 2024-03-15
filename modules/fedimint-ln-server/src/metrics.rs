use fedimint_metrics::prometheus::register_int_counter_with_registry;
use fedimint_metrics::{
    histogram_opts, lazy_static, opts, register_histogram_with_registry, Histogram, IntCounter,
    AMOUNTS_BUCKETS_SATS, REGISTRY,
};

lazy_static! {
    pub static ref LN_INCOMING_OFFER: IntCounter = register_int_counter_with_registry!(
        opts!("ln_incoming_offer", "contracts::IncomingContractOffer"),
        REGISTRY
    )
    .unwrap();
    pub static ref LN_OUTPUT_OUTCOME_CANCEL_OUTGOING_CONTRACT: IntCounter =
        register_int_counter_with_registry!(
            opts!(
                "ln_output_outcome_cancel_outgoing_contract",
                "LightningOutputOutcome::CancelOutgoingContract"
            ),
            REGISTRY
        )
        .unwrap();
    pub static ref LN_FUNDED_CONTRACT_INCOMING: IntCounter = register_int_counter_with_registry!(
        opts!(
            "ln_funded_contract_incoming",
            "contracts::FundedContract::Incoming"
        ),
        REGISTRY
    )
    .unwrap();
    pub static ref LN_FUNDED_CONTRACT_OUTGOING: IntCounter = register_int_counter_with_registry!(
        opts!(
            "ln_funded_contract_outgoing",
            "contracts::FundedContract::Outgoing"
        ),
        REGISTRY
    )
    .unwrap();
    pub static ref LN_FUNDED_CONTRACT_INCOMING_ACCOUNT_AMOUNTS_SATS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "ln_funded_contract_incoming_account_amounts_sats",
                "contracts::FundedContract::Incoming account amount in sats",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            REGISTRY
        )
        .unwrap();
    pub static ref LN_FUNDED_CONTRACT_OUTGOING_ACCOUNT_AMOUNTS_SATS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "ln_funded_contract_outgoing_account_amounts_sats",
                "contracts::FundedContract::Outgoing account amounts in sats",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            REGISTRY
        )
        .unwrap();
}

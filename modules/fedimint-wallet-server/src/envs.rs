use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_MODULE_WALLET;
use fedimint_wallet_common::FEERATE_MULTIPLIER_DEFAULT;
use tracing::warn;

pub const FM_WALLET_FEERATE_MULTIPLIER_ENV: &str = "FM_WALLET_FEERATE_MULTIPLIER";

pub fn get_feerate_multiplier() -> f64 {
    if let Ok(mult) = std::env::var(FM_WALLET_FEERATE_MULTIPLIER_ENV) {
        match mult.parse::<f64>() {
            Ok(mult) => return mult.clamp(1.0, 32.0),
            Err(err) => {
                warn!(
                    target: LOG_MODULE_WALLET,
                    err = %err.fmt_compact(),
                    "Invalid fee multiplier string"
                );
            }
        }
    }

    FEERATE_MULTIPLIER_DEFAULT
}

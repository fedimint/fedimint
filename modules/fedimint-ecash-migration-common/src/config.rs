use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, plugin_types_trait_impl_config};
use serde::{Deserialize, Serialize};

use crate::EcashMigrationCommonInit;

/// Parameters necessary to generate this module's configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParams {
    pub local: EcashMigrationGenParamsLocal,
    pub consensus: EcashMigrationGenParamsConsensus,
}

/// Local parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParamsLocal {}

/// Consensus parameters for config generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcashMigrationGenParamsConsensus {}

impl Default for EcashMigrationGenParams {
    fn default() -> Self {
        Self {
            local: EcashMigrationGenParamsLocal {},
            consensus: EcashMigrationGenParamsConsensus {},
        }
    }
}

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcashMigrationConfig {
    pub private: EcashMigrationConfigPrivate,
    pub consensus: EcashMigrationConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct EcashMigrationClientConfig;

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct EcashMigrationConfigConsensus {
    // TODO: make dynamic eventually
    pub fee_config: FeeConfig,
}

/// Static fee config of the module
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct FeeConfig {
    /// Fee per uploaded origin spend book entry
    pub spend_book_entry_fee: Amount,
    /// Fee for creating a new transfer
    pub transfer_creation_fee: Amount,
    /// Fee per funding of an existing transfer
    pub transfer_funding_fee: Amount,
    /// Fee per redemption of a single note from a transfer
    pub transfer_redeem_fee: Amount,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            // Give a little discount, so fees paid to the original federation can cover the
            // transfer request
            spend_book_entry_fee: Amount::from_msats(75),
            transfer_creation_fee: Amount::ZERO,
            transfer_funding_fee: Amount::ZERO,
            // Use the same fee as for the normal ecash module (if fees are enabled)
            transfer_redeem_fee: Amount::from_msats(100),
        }
    }
}

impl FeeConfig {
    pub fn creation_fee(&self, spend_book_entries: u64) -> Option<Amount> {
        self.transfer_creation_fee
            .checked_add(self.spend_book_entry_fee.checked_mul(spend_book_entries)?)
    }
}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcashMigrationConfigPrivate;

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    EcashMigrationCommonInit,
    EcashMigrationGenParams,
    EcashMigrationGenParamsLocal,
    EcashMigrationGenParamsConsensus,
    EcashMigrationConfig,
    EcashMigrationConfigPrivate,
    EcashMigrationConfigConsensus,
    EcashMigrationClientConfig
);

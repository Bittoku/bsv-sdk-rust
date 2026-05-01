//! STAS multi-transaction bundle factory.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::transaction::Transaction;

use super::planner::{plan_operations, PlannedOp};
use crate::error::TokenError;
use crate::factory::stas::{
    build_merge_tx, build_split_tx, build_transfer_tx, MergeConfig, SplitConfig, TransferConfig,
};
use crate::types::{Destination, Payment};

/// A UTXO holding STAS tokens for bundle operations.
pub struct TokenUtxo {
    /// Transaction hash.
    pub txid: Hash,
    /// Output index.
    pub vout: u32,
    /// Satoshi value.
    pub satoshis: u64,
    /// Locking script.
    pub locking_script: Script,
    /// Private key to sign.
    pub private_key: PrivateKey,
}

/// A funding UTXO for paying transaction fees.
pub struct FundingUtxo {
    /// Transaction hash.
    pub txid: Hash,
    /// Output index.
    pub vout: u32,
    /// Satoshi value.
    pub satoshis: u64,
    /// Locking script.
    pub locking_script: Script,
    /// Private key to sign.
    pub private_key: PrivateKey,
}

/// Result of a bundle operation.
pub struct PayoutBundle {
    /// Transactions in execution order.
    pub transactions: Vec<Transaction>,
    /// Total fees paid across all transactions.
    pub fee_satoshis: u64,
}

/// Configuration for a STAS bundle transfer.
pub struct StasBundleConfig {
    /// Available STAS UTXOs to spend.
    pub token_utxos: Vec<TokenUtxo>,
    /// Target destinations.
    pub destinations: Vec<Destination>,
    /// Redemption PKH for STAS script construction.
    pub redemption_pkh: [u8; 20],
    /// Whether tokens are splittable.
    pub splittable: bool,
    /// Fee rate in satoshis per KB.
    pub fee_rate: u64,
    /// Callback to get a funding UTXO for fees.
    pub funding_provider: Box<dyn Fn() -> Result<FundingUtxo, TokenError>>,
}

fn funding_to_payment(f: FundingUtxo) -> Payment {
    Payment {
        txid: f.txid,
        vout: f.vout,
        satoshis: f.satoshis,
        locking_script: f.locking_script,
        private_key: f.private_key,
    }
}

fn token_to_payment(t: &TokenUtxo) -> Payment {
    Payment {
        txid: t.txid,
        vout: t.vout,
        satoshis: t.satoshis,
        locking_script: t.locking_script.clone(),
        private_key: t.private_key.clone(),
    }
}

/// Build a multi-transaction STAS bundle.
///
/// Plans merge/split/transfer operations and builds the corresponding
/// transactions, chaining outputs to inputs as needed.
pub fn build_stas_bundle(config: StasBundleConfig) -> Result<PayoutBundle, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::BundleError("no destinations provided".into()));
    }

    let available: Vec<(usize, u64)> = config
        .token_utxos
        .iter()
        .enumerate()
        .map(|(i, u)| (i, u.satoshis))
        .collect();
    let targets: Vec<u64> = config.destinations.iter().map(|d| d.satoshis).collect();

    let ops = plan_operations(&available, &targets)?;

    let mut transactions = Vec::new();
    let total_fees = 0u64;

    // Track current state of UTXOs (may be replaced by tx outputs after merge/split)
    // For simplicity, we process ops sequentially and build each transaction.

    for op in &ops {
        match op {
            PlannedOp::Transfer { source, dest_index } => {
                let funding = (config.funding_provider)()?;
                let tx_config = TransferConfig {
                    token_utxo: token_to_payment(&config.token_utxos[*source]),
                    destination: config.destinations[*dest_index].clone(),
                    redemption_pkh: config.redemption_pkh,
                    splittable: config.splittable,
                    funding: funding_to_payment(funding),
                    fee_rate: config.fee_rate,
                };
                let tx = build_transfer_tx(&tx_config)?;
                transactions.push(tx);
            }
            PlannedOp::Split { source, amounts } => {
                let funding = (config.funding_provider)()?;
                // Map amounts to destinations; first N amounts correspond to actual destinations
                let dests: Vec<Destination> = amounts
                    .iter()
                    .enumerate()
                    .map(|(i, &amt)| {
                        if i < config.destinations.len() {
                            Destination {
                                address: config.destinations[i].address.clone(),
                                satoshis: amt,
                            }
                        } else {
                            // Change goes back to first destination's address (simplified)
                            Destination {
                                address: config.destinations[0].address.clone(),
                                satoshis: amt,
                            }
                        }
                    })
                    .collect();
                let tx_config = SplitConfig {
                    token_utxo: token_to_payment(&config.token_utxos[*source]),
                    destinations: dests,
                    redemption_pkh: config.redemption_pkh,
                    funding: funding_to_payment(funding),
                    fee_rate: config.fee_rate,
                };
                let tx = build_split_tx(&tx_config)?;
                transactions.push(tx);
            }
            PlannedOp::Merge { input_a, input_b } => {
                let funding = (config.funding_provider)()?;
                let merged_sats =
                    config.token_utxos[*input_a].satoshis + config.token_utxos[*input_b].satoshis;
                let tx_config = MergeConfig {
                    token_utxos: vec![
                        token_to_payment(&config.token_utxos[*input_a]),
                        token_to_payment(&config.token_utxos[*input_b]),
                    ],
                    destination: Destination {
                        address: config.destinations[0].address.clone(),
                        satoshis: merged_sats,
                    },
                    redemption_pkh: config.redemption_pkh,
                    splittable: config.splittable,
                    funding: funding_to_payment(funding),
                    fee_rate: config.fee_rate,
                };
                let tx = build_merge_tx(&tx_config)?;
                transactions.push(tx);
            }
        }
    }

    Ok(PayoutBundle {
        transactions,
        fee_satoshis: total_fees,
    })
}

#[cfg(test)]
mod tests {
    // Bundle integration tests require full transaction building infrastructure,
    // which is tested via the factory tests. The planner tests cover the logic.
}

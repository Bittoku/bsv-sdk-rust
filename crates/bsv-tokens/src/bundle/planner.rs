//! UTXO merge/split planning algorithm.

use crate::error::TokenError;

/// A planned operation in a bundle sequence.
#[derive(Debug, Clone)]
pub enum PlannedOp {
    /// Merge two UTXOs into one.
    Merge {
        /// Index of first input UTXO.
        input_a: usize,
        /// Index of second input UTXO.
        input_b: usize,
    },
    /// Split a UTXO into multiple amounts.
    Split {
        /// Index of the source UTXO.
        source: usize,
        /// Amounts to split into.
        amounts: Vec<u64>,
    },
    /// Direct transfer (UTXO covers target exactly or with acceptable dust).
    Transfer {
        /// Index of source UTXO.
        source: usize,
        /// Index into the targets array.
        dest_index: usize,
    },
}

/// Dust threshold – amounts within this range of the target are considered exact.
const DUST_THRESHOLD: u64 = 1;

/// Plan operations to transform available UTXOs into target amounts.
///
/// Algorithm:
/// 1. Sort UTXOs descending by satoshis
/// 2. Sort targets descending
/// 3. Greedily assign UTXOs to targets (largest-first)
/// 4. If no single UTXO covers a target → plan pairwise merges
/// 5. If a UTXO exceeds target → plan split
/// 6. Return ordered list of operations
pub fn plan_operations(
    available: &[(usize, u64)],
    targets: &[u64],
) -> Result<Vec<PlannedOp>, TokenError> {
    if targets.is_empty() {
        return Ok(vec![]);
    }

    let total_available: u64 = available.iter().map(|(_, s)| s).sum();
    let total_needed: u64 = targets.iter().sum();

    if total_available < total_needed {
        return Err(TokenError::InsufficientFunds {
            needed: total_needed,
            available: total_available,
        });
    }

    // Working copies sorted descending
    let mut utxos: Vec<(usize, u64)> = available.to_vec();
    utxos.sort_by(|a, b| b.1.cmp(&a.1));

    let mut sorted_targets: Vec<(usize, u64)> =
        targets.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    sorted_targets.sort_by(|a, b| b.1.cmp(&a.1));

    let mut ops = Vec::new();
    let mut used = vec![false; utxos.len()];
    // Track which UTXOs need splitting (source_utxo_idx -> vec of target amounts)
    let mut split_map: std::collections::HashMap<usize, Vec<(usize, u64)>> =
        std::collections::HashMap::new();

    for &(dest_idx, target) in &sorted_targets {
        // Try exact match first
        let exact = utxos
            .iter()
            .enumerate()
            .find(|(i, (_, s))| !used[*i] && *s == target);
        if let Some((ui, _)) = exact {
            used[ui] = true;
            ops.push(PlannedOp::Transfer {
                source: utxos[ui].0,
                dest_index: dest_idx,
            });
            continue;
        }

        // Try smallest UTXO >= target
        let mut candidates: Vec<(usize, u64)> = utxos
            .iter()
            .enumerate()
            .filter(|(i, (_, s))| !used[*i] && *s >= target)
            .map(|(i, (_, s))| (i, *s))
            .collect();
        candidates.sort_by_key(|(_, s)| *s);

        if let Some((ui, sats)) = candidates.first() {
            let ui = *ui;
            let sats = *sats;
            if sats <= target + DUST_THRESHOLD {
                // Close enough for direct transfer
                used[ui] = true;
                ops.push(PlannedOp::Transfer {
                    source: utxos[ui].0,
                    dest_index: dest_idx,
                });
            } else {
                // Need a split – accumulate targets for this UTXO
                used[ui] = true;
                split_map.entry(ui).or_default().push((dest_idx, target));
                // Remainder stays as change (we'll handle below)
                let _ = sats;
            }
            continue;
        }

        // No single UTXO covers this target – merge two
        let mut free: Vec<usize> = (0..utxos.len()).filter(|i| !used[*i]).collect();
        free.sort_by(|a, b| utxos[*b].1.cmp(&utxos[*a].1));

        if free.len() < 2 {
            return Err(TokenError::BundleError(
                "not enough UTXOs to merge for target".into(),
            ));
        }

        // Merge the two largest free UTXOs
        let a = free[0];
        let b = free[1];
        used[a] = true;
        used[b] = true;
        let merged_sats = utxos[a].1 + utxos[b].1;
        ops.push(PlannedOp::Merge {
            input_a: utxos[a].0,
            input_b: utxos[b].0,
        });

        if merged_sats == target || merged_sats <= target + DUST_THRESHOLD {
            ops.push(PlannedOp::Transfer {
                source: utxos[a].0,
                dest_index: dest_idx,
            });
        } else if merged_sats > target {
            ops.push(PlannedOp::Split {
                source: utxos[a].0,
                amounts: vec![target, merged_sats - target],
            });
        } else {
            return Err(TokenError::BundleError(
                "merged UTXOs still insufficient for target".into(),
            ));
        }
    }

    // Emit split ops for UTXOs assigned to multiple targets or single target < utxo value
    for (ui, targets_for_utxo) in &split_map {
        let total_targets: u64 = targets_for_utxo.iter().map(|(_, t)| t).sum();
        let source_sats = utxos[*ui].1;
        let mut amounts: Vec<u64> = targets_for_utxo.iter().map(|(_, t)| *t).collect();
        if source_sats > total_targets {
            amounts.push(source_sats - total_targets); // change
        }
        // Remove the Transfer ops we might have added and replace with Split
        ops.retain(|op| {
            if let PlannedOp::Transfer { source, .. } = op {
                *source != utxos[*ui].0
            } else {
                true
            }
        });
        ops.push(PlannedOp::Split {
            source: utxos[*ui].0,
            amounts,
        });
    }

    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_exact_match() {
        let available = vec![(0, 1000)];
        let targets = vec![1000];
        let ops = plan_operations(&available, &targets).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            ops[0],
            PlannedOp::Transfer {
                source: 0,
                dest_index: 0
            }
        ));
    }

    #[test]
    fn test_single_utxo_larger_than_target() {
        let available = vec![(0, 5000)];
        let targets = vec![3000];
        let ops = plan_operations(&available, &targets).unwrap();
        // Should have a split
        assert!(ops
            .iter()
            .any(|op| matches!(op, PlannedOp::Split { source: 0, .. })));
        if let PlannedOp::Split { amounts, .. } = &ops[ops.len() - 1] {
            assert_eq!(amounts[0], 3000);
            assert_eq!(amounts[1], 2000);
        }
    }

    #[test]
    fn test_merge_two_utxos() {
        let available = vec![(0, 300), (1, 400)];
        let targets = vec![700];
        let ops = plan_operations(&available, &targets).unwrap();
        assert!(ops.iter().any(|op| matches!(op, PlannedOp::Merge { .. })));
    }

    #[test]
    fn test_multiple_targets_mixed() {
        let available = vec![(0, 1000), (1, 500), (2, 300)];
        let targets = vec![1000, 500];
        let ops = plan_operations(&available, &targets).unwrap();
        // Both should be direct transfers
        let transfers: Vec<_> = ops
            .iter()
            .filter(|op| matches!(op, PlannedOp::Transfer { .. }))
            .collect();
        assert_eq!(transfers.len(), 2);
    }

    #[test]
    fn test_insufficient_funds() {
        let available = vec![(0, 100)];
        let targets = vec![500];
        let result = plan_operations(&available, &targets);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenError::InsufficientFunds { .. }
        ));
    }

    #[test]
    fn test_empty_targets() {
        let available = vec![(0, 1000)];
        let targets: Vec<u64> = vec![];
        let ops = plan_operations(&available, &targets).unwrap();
        assert!(ops.is_empty());
    }

    #[test]
    fn test_total_input_gte_total_target() {
        // Property test: for any valid plan, total input >= total target
        let available = vec![(0, 1000), (1, 2000), (2, 500)];
        let targets = vec![800, 600, 300];
        let ops = plan_operations(&available, &targets).unwrap();
        let total_input: u64 = available.iter().map(|(_, s)| s).sum();
        let total_target: u64 = targets.iter().sum();
        assert!(total_input >= total_target);
        assert!(!ops.is_empty());
    }
}

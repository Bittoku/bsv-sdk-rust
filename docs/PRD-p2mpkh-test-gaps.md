# PRD: P2MPKH Integration Test Gaps — bsv-sdk-rust

**Date:** 2026-03-26
**Author:** HAL9000 (code review)
**Builder:** GLaDOS
**Status:** Ready for implementation
**Priority:** High — the multi-key sign() codepath is untested

---

## 1. Context

Commit `4c6a415` added P2MPKH support across the Rust SDK. The core `MultisigScript` type in `bsv-transaction` has 14 solid tests. The `bsv-tokens` crate added 15 tests for `SigningKey`, `OwnerAddress`, template constructors, and estimate_length.

However, no test ever calls `sign()` on a P2MPKH template. The entire signing codepath — which produces actual on-chain unlocking scripts — is dead code from a testing perspective. The factory wiring with multi signing keys is also untested.

### Crate layout

- `crates/bsv-transaction/src/template/p2mpkh.rs` — standalone P2MPKH template
- `crates/bsv-tokens/src/template/stas.rs` — `StasMpkhUnlockingTemplate`
- `crates/bsv-tokens/src/template/stas3.rs` — `DstasMpkhUnlockingTemplate`
- `crates/bsv-tokens/src/types.rs` — `SigningKey`, `OwnerAddress`, `Payment`, `TokenInput`
- `crates/bsv-tokens/src/factory/stas.rs` — STAS factories (issue, transfer, split, merge, redeem)
- `crates/bsv-tokens/src/factory/stas3.rs` — STAS3 factories

## 2. Gaps to Fill

### Gap 1: `StasMpkhUnlockingTemplate::sign()` — the critical path

**File:** `crates/bsv-tokens/src/template/stas.rs`

The `sign()` method produces `<sig1>…<sigM> <serialized_multisig_script>`. Never called in any test.

**What to test:**

1. **2-of-3 sign produces correct script structure**: Build a mock transaction with a `source_tx_output` (any locking script + satoshis). Call `sign()`. Verify:
   - The script has exactly M+1 push-data chunks (M signatures + 1 multisig script)
   - Each signature chunk is 71–73 bytes (DER + sighash flag)
   - Last byte of each signature equals `0x41` (SIGHASH_ALL_FORKID)
   - The final chunk equals `multisig.to_bytes()`

2. **1-of-1 sign**: Verify it works at the minimum threshold.

3. **3-of-5 sign**: Verify higher thresholds produce the correct number of signatures.

4. **Missing source output returns error**: Call `sign()` on an input without `source_tx_output`.

5. **Signatures are unique per key**: With a 2-of-3, verify sig[0] ≠ sig[1].

**Helper for building mock transactions:**

```rust
fn mock_tx_with_source(satoshis: u64) -> Transaction {
    use bsv_transaction::transaction::{Transaction, TransactionInput, TransactionOutput};
    use bsv_script::Script;

    let locking_script = Script::from_asm_string("OP_DUP OP_HASH160 ...").unwrap();
    // Or just use a minimal script — the sighash computation only needs bytes + satoshis

    let source_output = TransactionOutput {
        satoshis,
        locking_script: locking_script.clone(),
    };

    let input = TransactionInput {
        source_txid: [0u8; 32],  // dummy
        source_vout: 0,
        source_tx_output: Some(source_output),
        unlocking_script: Script::new(),
        sequence: 0xFFFFFFFF,
    };

    Transaction {
        version: 1,
        inputs: vec![input],
        outputs: vec![TransactionOutput {
            satoshis: satoshis - 1000,
            locking_script,
        }],
        lock_time: 0,
    }
}
```

Adapt field names to match the actual struct definitions — check `bsv-transaction/src/transaction.rs` for exact field names. The key requirement is that `input.source_tx_output()` returns `Some(...)`.

### Gap 2: `DstasMpkhUnlockingTemplate::sign()` — mirror of Gap 1

**File:** `crates/bsv-tokens/src/template/stas3.rs`

Identical structure to STAS. Test at minimum:

1. **2-of-3 sign**: Script structure, signature count, multisig script chunk
2. **Missing source output error**
3. **Carries spend_type correctly** (verify the template stores it — though spend_type doesn't affect the unlocking script format yet)

### Gap 3: `P2MPKH::sign()` — standalone bare multisig

**File:** `crates/bsv-transaction/src/template/p2mpkh.rs`

The `UnlockingScriptTemplate` implementation produces `OP_0 <sig1>…<sigM>`. Never tested.

**What to test:**

1. **2-of-3 sign**: Build mock tx, call `sign()`, verify:
   - Script starts with an empty push (OP_0 / empty data)
   - Followed by exactly M signature pushes
   - Each signature is DER + sighash flag byte
   
2. **1-of-1 sign**: Minimum case.

3. **Missing source output error**

4. **Custom sighash flag**: Pass a non-default flag, verify it appears in signature bytes.

### Gap 4: Factory integration with `SigningKey::Multi`

**File:** `crates/bsv-tokens/src/factory/stas.rs`

No factory operation has been tested with a multi signing key. The refactored code paths include:
- `sign_token_and_funding_inputs()` dispatching via `unlock_from_signing_key`
- Change address derivation from `funding.signing_key.hash160()` (MPKH path)
- P2MPKH funding input signing (not P2PKH)

**What to test:**

Pick the simplest factory operation (likely `transfer`). Build config with:
- `token_utxo.signing_key = SigningKey::Multi { ... }`
- `funding.signing_key = SigningKey::Multi { ... }`

Verify:
- Factory returns `Ok(tx)` — doesn't crash
- The transaction has unlocking scripts set on all inputs
- The unlocking scripts are non-empty
- Change output (if present) contains the MPKH-derived address, not a PKH

### Gap 5: BTG rejection of P2MPKH

**File:** Likely in `crates/bsv-tokens/src/factory/btg.rs` or similar

The commit message claims "BTG factories reject P2MPKH with clear error (not yet supported)." This needs a test:

1. Pass `SigningKey::Multi { ... }` to a BTG factory operation
2. Assert the result is `Err(...)` with a message mentioning P2MPKH or multisig not supported

### Gap 6: `estimate_length` across multiple m-of-n combinations

**Files:** All three templates

The existing tests only check 2-of-3. Add:
- 1-of-1: Verify formula produces correct value
- 3-of-5: Verify formula produces correct value
- For STAS/STAS3: `m * 73 + 3 + n * 34 + 3`
- For standalone P2MPKH: `1 + m * 73` (OP_0 + sigs)

## 3. Implementation Notes

### Extracting script chunks for verification

After calling `sign()`, you need to inspect the resulting `Script`. Check how `Script` exposes its data — it may have methods like `to_bytes()`, or you may need to parse the raw bytes to count push-data operations.

A practical approach: convert the script to bytes, then verify:
- Total byte length is in expected range
- For STAS P2MPKH: no OP_0 prefix; starts with a push-data (signature)
- For standalone P2MPKH: starts with `OP_0` (0x00 or empty push)
- The last N bytes match `multisig.to_bytes()` (for STAS/STAS3 only)

### Signature byte verification

DER-encoded ECDSA signatures are typically 70-72 bytes. With the 1-byte sighash flag appended, each signature push is 71-73 bytes. The push-data prefix adds 1 byte (OP_PUSH + length for data ≤ 75 bytes).

### Running tests

```bash
cd ~/work/bsv-sdk-rust
cargo test --workspace
```

All 497 existing tests must still pass.

## 4. Acceptance Criteria

- [ ] `StasMpkhUnlockingTemplate::sign()` tested with 2-of-3, 1-of-1, 3-of-5 — verifies script structure (chunk count, signature bytes, multisig script)
- [ ] `DstasMpkhUnlockingTemplate::sign()` tested with at least 2-of-3 — verifies script structure
- [ ] `P2MPKH::sign()` (standalone) tested with 2-of-3 — verifies OP_0 prefix + signatures
- [ ] Missing source output error tested for all three template types
- [ ] At least one STAS factory operation tested end-to-end with `SigningKey::Multi`
- [ ] BTG factory rejection of `SigningKey::Multi` tested
- [ ] `estimate_length` verified for at least 3 different m-of-n combos per template
- [ ] All existing 497 tests still pass
- [ ] New tests verify structure and correctness, not just `is_ok()`
- [ ] Commit with identity: `Jerry David Chan <digitsu@gmail.com>`

## 5. Non-Goals

- On-chain transaction verification
- Modifying any implementation code
- Adding new features
- Testing the actual STAS on-chain script verification logic

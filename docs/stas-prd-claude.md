# Plan: `bsv-stas` Crate — STAS-20 Token Protocol

## Context

The bsv-sdk-rust workspace has 7 domain crates + 1 facade but **no token layer**. The STAS protocol is the primary native L1 token standard on BSV — tokens are satoshis with script-enforced transfer rules, no external oracle needed. Adding a `bsv-stas` crate enables stablecoin, utility token, and NFT use cases. This plan covers STAS-20 (fungible tokens with redemption), the most common variant.

The API uses **Config structs** (matching the existing `lock()`/`unlock()` functional style), not a fluent builder.

## Files to Create

```
crates/bsv-stas/
├── Cargo.toml
└── src/
    ├── lib.rs              # Crate root, module declarations, re-exports
    ├── error.rs            # StasError enum (thiserror)
    ├── schema.rs           # TokenScheme — contract JSON metadata
    ├── token_id.rs         # TokenId — newtype over issuance address
    ├── outpoint.rs         # StasOutPoint — spendable STAS UTXO descriptor
    ├── script/
    │   ├── mod.rs          # Script sub-module re-exports
    │   ├── locking.rs      # build_stas20_locking_script(), is_stas()
    │   └── reader.rs       # StasScriptReader — parse token data from scripts
    ├── contract.rs         # build_contract_tx()
    ├── issue.rs            # build_issue_tx()
    ├── transfer.rs         # build_transfer_tx()
    ├── split.rs            # build_split_tx()
    ├── redeem.rs           # build_redeem_tx()
    ├── template/
    │   ├── mod.rs          # Template sub-module
    │   └── stas20.rs       # Stas20Unlocker implements UnlockingScriptTemplate
    └── tests.rs            # Unit/integration tests
```

## Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Add `"crates/bsv-stas"` to members, add `bsv-stas = { path = "crates/bsv-stas" }` to `[workspace.dependencies]` |
| `bsv-sdk/Cargo.toml` | Add `bsv-stas = { workspace = true }` dependency |
| `bsv-sdk/src/lib.rs` | Add `pub use bsv_stas as stas;` re-export |

## Critical Existing Files to Reference

- `crates/bsv-transaction/src/template/mod.rs` — `UnlockingScriptTemplate` trait (implement for STAS)
- `crates/bsv-transaction/src/template/p2pkh.rs` — Pattern to follow: `lock()`, `unlock()`, `P2PKH` struct
- `crates/bsv-transaction/src/transaction.rs` — `Transaction` struct, `add_input()`, `add_output()`, `calc_input_signature_hash()`
- `crates/bsv-script/src/script.rs` — `Script::new()`, `append_push_data()`, `append_opcodes()`, `is_data()`
- `crates/bsv-script/src/opcodes.rs` — All opcode constants
- `crates/bsv-message/src/error.rs` — Error pattern with structured fields
- `crates/bsv-primitives/src/ec/private_key.rs` — `PrivateKey` for signing

## Implementation Steps

### Step 1: Workspace scaffolding
- Create `crates/bsv-stas/` directory
- Create `Cargo.toml` with workspace-inherited metadata
- Dependencies: `bsv-primitives`, `bsv-script`, `bsv-transaction`, `hex`, `thiserror`, `serde`, `serde_json`
- Add to workspace members and `[workspace.dependencies]`
- Stub `lib.rs` with `#![deny(missing_docs)]`

### Step 2: Error types (`error.rs`)
```rust
#[derive(Debug, thiserror::Error)]
pub enum StasError {
    InvalidSchema(String),
    InvalidTokenId(String),
    InvalidScript(String),
    SupplyMismatch(String),
    InsufficientFunds(String),
    NotSplittable,
    Transaction(#[from] TransactionError),
    Script(#[from] ScriptError),
    Primitives(#[from] PrimitivesError),
    Json(#[from] serde_json::Error),
    Other(String),
}
```

### Step 3: Core types
- **`schema.rs`** — `TokenScheme` struct with serde JSON (de)serialization. Fields: `token_name`, `token_id`, `issuer_name`, `symbol`, `description`, `icon`, `terms`, `splittable`, `total_supply`. Methods: `to_json_bytes()`, `from_json_bytes()`.
- **`token_id.rs`** — `TokenId` newtype wrapping address string + 20-byte PKH. Methods: `from_address()`, `from_string()`, `as_str()`, `public_key_hash()`.
- **`outpoint.rs`** — `StasOutPoint` struct: `txid`, `vout`, `locking_script`, `satoshis`, `token_id`.

### Step 4: STAS script builder and reader (`script/`)
- **`locking.rs`** — `build_stas20_locking_script(destination_pkh, token_id, issuance_txid) -> Script`
  - Reverse-engineer the exact STAS-20 script template from the stas-js / dxs-stas-sdk TypeScript source
  - The script contains: P2PKH spending logic + STAS enforcement logic + OP_RETURN trailer with token ID
  - Also: `is_stas(script) -> bool` classifier
- **`reader.rs`** — `StasScriptReader` parses token_id, issuance_txid, destination_pkh from a STAS locking script

### Step 5: STAS unlocking template (`template/stas20.rs`)
- `unlock(private_key, token_id, sighash_flag) -> Stas20Unlocker`
- `Stas20Unlocker` implements `UnlockingScriptTemplate` from bsv-transaction
- `sign()` computes sighash and produces `<sig> <pubkey>` unlocking script
- `estimate_length()` returns appropriate estimate for STAS unlocking scripts

### Step 6: Transaction builders
Each builder takes a `*Config` struct and returns `Result<Transaction, StasError>`:

- **`contract.rs`** — `build_contract_tx(ContractConfig)`: Creates OP_RETURN output with TokenScheme JSON. Input: funding P2PKH. Outputs: OP_RETURN (0 sats) + change.
- **`issue.rs`** — `build_issue_tx(IssueConfig)`: Spends contract UTXO → STAS output(s). Inputs: contract UTXO + funding P2PKH. Outputs: STAS-20 locking script (full supply) + change.
- **`transfer.rs`** — `build_transfer_tx(TransferConfig)`: 1:1 move. Inputs: STAS + funding. Outputs: STAS to destination + change.
- **`split.rs`** — `build_split_tx(SplitConfig)`: 1:2 split. Validates amounts sum correctly and schema allows splitting. Inputs: STAS + funding. Outputs: 2 STAS + change.
- **`redeem.rs`** — `build_redeem_tx(RedeemConfig)`: Burns token → P2PKH. Inputs: STAS + funding. Outputs: P2PKH (full satoshis) + change.

### Step 7: Facade integration
- Add `bsv-stas` dependency to `bsv-sdk/Cargo.toml`
- Add `pub use bsv_stas as stas;` to `bsv-sdk/src/lib.rs`

### Step 8: Tests (`tests.rs`)
- `test_token_scheme_json_roundtrip`
- `test_token_id_from_address`
- `test_stas_locking_script_is_stas` / `test_p2pkh_is_not_stas`
- `test_stas_script_reader`
- `test_build_contract_tx` — verify OP_RETURN output
- `test_build_issue_tx` — verify STAS output
- `test_build_transfer_tx` — verify destination
- `test_build_split_tx_valid` / `test_build_split_tx_mismatch` / `test_build_split_non_splittable`
- `test_build_redeem_tx` — verify P2PKH output
- `test_stas20_unlocker_estimate_length`

## STAS Script Research Required

The `build_stas20_locking_script()` function requires extracting the exact byte layout from the TypeScript SDKs:
- Primary source: `https://github.com/TAAL-GmbH/stas-js` (lib/ directory)
- Secondary source: `https://github.com/dxsapp/dxs-stas-sdk` (src/ directory)
- Look for the script template bytes, OP_RETURN structure, and how token ID / issuance txid are embedded

This will be done as part of Step 4 implementation.

## Future Phases (not in this plan)

- **Phase 2**: `merge.rs`, `swap.rs`, `redeem_split.rs`
- **Phase 3**: STAS-50, STAS-789, STAS3 variants, `DstasBundleFactory`

## Verification

1. `cargo build --workspace` — compiles without errors
2. `cargo test --workspace` — all tests pass (existing + new)
3. `cargo clippy --workspace -- -D warnings` — no warnings
4. `cargo fmt --all -- --check` — formatted correctly
5. Verify `bsv_sdk::stas::*` re-exports work from the facade crate

# PRD: `bsv-tokens` — STAS Token Support for bsv-sdk-rust

**Author:** CLU (consolidated from HAL9000 + Claude drafts)
**Date:** 2026-02-16
**Status:** Final — Approved for Implementation
**Reference:** [dxs-stas-sdk](https://github.com/dxsapp/dxs-stas-sdk) (TypeScript)
**Architecture:** [stas-architecture.md](./stas-architecture.md)
**Comparison:** [stas-plan-comparison.md](./stas-plan-comparison.md)

---

## 1. Goal

Add a `bsv-tokens` crate to the BSV Rust SDK that enables creation, transfer, and management of STAS and DSTAS tokens on the BSV blockchain. The crate builds on top of the existing SDK primitives (keys, scripts, transactions, wallets) and provides both low-level script construction and high-level transaction orchestration.

## 2. Non-Goals

- On-chain indexing or UTXO tracking (consumers provide their own backend)
- Network broadcasting (consumers handle submission to miners/ARC)
- GUI or CLI tooling
- Support for non-STAS token protocols (BRC-20, Run, etc.)

## 3. Design Decisions (Resolved)

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Async strategy for bundle factory | Generic `Fn` bounds returning `impl Future` | Avoids `async-trait` dep; consistent with existing transport traits in SDK |
| 2 | Signing abstraction | Use existing `UnlockingScriptTemplate` trait from `bsv-transaction` | Already defined and implemented for P2PKH; extend with STAS/DSTAS template impls |
| 3 | Script template versions | Build STAS 3.0 only, read v1/v2/STAS 3.0 | STAS 3.0 (stas3-freeze-multisig) is current; reader should classify legacy outputs found on-chain |
| 4 | WASM compatibility | Core crate is `no_std + alloc`; bundle factory behind `feature = "bundle"` requiring `std` | Clean boundary; bundle is the only module needing async I/O |
| 5 | Factory function signatures | `*Config` structs for 4+ parameter functions; direct params for simple functions | Idiomatic Rust; enables `#[derive(Default)]` and `..Default::default()` struct update syntax; prevents argument-order bugs; consistent with existing `interpreter::Config` pattern in SDK |
| 6 | TokenScheme serialization | Dual: `to_bytes()`/`from_bytes()` for on-chain embedding + `serde` JSON for human-readable interchange | On-chain contract TXs use compact bytes; external tooling and tests benefit from JSON |
| 7 | Documentation enforcement | `#![deny(missing_docs)]` at crate root | All public API surfaces must be documented; catches undocumented items at compile time |

## 4. Critical Existing Files to Reference

These files in the existing SDK define the traits, types, and patterns that `bsv-tokens` must integrate with:

| File | Relevance |
|------|-----------|
| `crates/bsv-transaction/src/template/mod.rs` | `UnlockingScriptTemplate` trait — implement for STAS/DSTAS |
| `crates/bsv-transaction/src/template/p2pkh.rs` | Pattern to follow: `lock()`, `unlock()`, struct impl |
| `crates/bsv-transaction/src/transaction.rs` | `Transaction` struct, `add_input()`, `add_output()`, `calc_input_signature_hash()` |
| `crates/bsv-script/src/script.rs` | `Script::new()`, `append_push_data()`, `append_opcodes()` |
| `crates/bsv-script/src/opcodes.rs` | All opcode constants |
| `crates/bsv-script/src/interpreter/config.rs` | `Config` struct pattern precedent |
| `crates/bsv-primitives/src/ec/private_key.rs` | `PrivateKey` for signing |
| `crates/bsv-message/src/error.rs` | Error pattern with structured fields |

## 5. Crate Layout

```
crates/bsv-tokens/
├── Cargo.toml
└── src/
    ├── lib.rs                  # #![deny(missing_docs)], module declarations, re-exports
    ├── error.rs                # TokenError with thiserror
    ├── scheme.rs               # TokenScheme (serde + binary), Authority
    ├── token_id.rs             # TokenId newtype (address string + 20-byte PKH)
    ├── script_type.rs          # ScriptType enum
    ├── types.rs                # Payment, Destination, SpendType, ActionData, Config structs
    │
    ├── script/
    │   ├── mod.rs
    │   ├── templates.rs        # Byte-pattern constants for v1/v2/v3 classification
    │   ├── reader.rs           # read_locking_script() → ParsedScript
    │   ├── stas_builder.rs     # build_stas_locking_script()
    │   └── dstas_builder.rs    # build_dstas_locking_script(), flags, service fields
    │
    ├── template/
    │   ├── mod.rs
    │   ├── stas.rs             # UnlockingScriptTemplate impl for STAS spends
    │   └── dstas.rs            # UnlockingScriptTemplate impl for DSTAS spends (with spend_type)
    │
    ├── factory/
    │   ├── mod.rs
    │   ├── contract.rs         # build_contract_tx() — standalone contract TX builder
    │   ├── stas.rs             # STAS tx builders: issue, transfer, split, merge, redeem
    │   └── dstas.rs            # DSTAS tx builders: issue, base, freeze, unfreeze, swap flow
    │
    └── bundle/                 # Behind feature = "bundle"
        ├── mod.rs
        ├── planner.rs          # UTXO merge/split planning algorithm
        ├── stas_bundle.rs      # StasBundleFactory
        └── dstas_bundle.rs     # DstasBundleFactory
```

## 6. Dependencies

```toml
[dependencies]
bsv-primitives = { workspace = true }
bsv-script = { workspace = true }
bsv-transaction = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }

[dependencies.bsv-wallet]
workspace = true
optional = true

[features]
default = []
bundle = ["bsv-wallet"]        # Enables bundle factories (requires std + async)
```

## 7. Implementation Plan

### Phase T1: Foundation Types

**Scope:** `error.rs`, `scheme.rs`, `token_id.rs`, `script_type.rs`, `types.rs`
**Effort:** 1–2 days
**Dependencies:** `bsv-primitives` only

**Deliverables:**

**Error types (`error.rs`):**
```rust
/// Errors produced by the STAS token crate.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid token scheme: {0}")]
    InvalidScheme(String),
    #[error("token amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: u64, actual: u64 },
    #[error("invalid script: {0}")]
    InvalidScript(String),
    #[error("invalid destination: {0}")]
    InvalidDestination(String),
    #[error("invalid authority: {0}")]
    InvalidAuthority(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("not splittable: token scheme does not allow splitting")]
    NotSplittable,
    #[error("insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("bundle error: {0}")]
    BundleError(String),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Script(#[from] ScriptError),
    #[error(transparent)]
    Primitives(#[from] PrimitivesError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
```

**Core types:**
- `TokenScheme` struct with dual serialization:
  - `to_bytes()` / `from_bytes()` for on-chain contract TX OP_RETURN embedding
  - `#[derive(Serialize, Deserialize)]` for JSON interchange
  - Fields: `token_name`, `token_id`, `issuer_name`, `symbol`, `description`, `icon`, `terms`, `splittable`, `total_supply`, `version`, `divisible`, `freeze`
- `TokenId` newtype wrapping address string + 20-byte PKH
  - Methods: `from_address()`, `from_string()`, `as_str()`, `public_key_hash() -> &[u8; 20]`
- `Authority` struct for multisig freeze governance (m-of-n threshold + compressed pubkeys)
- `ScriptType` enum: `P2pkh`, `Stas`, `StasV2`, `Dstas`, `OpReturn`, `Unknown`
- `Payment` struct wrapping an `OutPoint` + signing key reference
- `Destination` struct: satoshis + address
- `DstasDestination`: satoshis + `DstasLockingParams`
- `DstasSpendType` enum: `Transfer = 1`, `FreezeUnfreeze = 2`, `Swap = 4`
- `ActionData` enum: `Swap { ... }`, `Custom(Vec<u8>)`

**Tests:**
- TokenScheme roundtrip serialization (to_bytes → from_bytes)
- TokenScheme JSON roundtrip (to_json_bytes → from_json_bytes)
- TokenId from_address and public_key_hash extraction
- Authority validation (m ≤ n, key lengths = 33 bytes)
- ScriptType Display/Debug

**Acceptance:** `cargo test -p bsv-tokens` passes, all types compile against `no_std + alloc`.

---

### Phase T2: Script Reader & Templates

**Scope:** `script/templates.rs`, `script/reader.rs`
**Effort:** 2–3 days
**Dependencies:** T1 + `bsv-script`

**STAS script research:** Extract exact byte layout from the TypeScript SDKs:
- Primary source: [TAAL stas-js](https://github.com/TAAL-GmbH/stas-js) (`lib/` directory)
- Secondary source: [dxs-stas-sdk](https://github.com/dxsapp/dxs-stas-sdk) (`src/` directory)
- Extract: script template bytes, OP_RETURN structure, token ID / issuance txid embedding

**Deliverables:**
- `templates.rs`: Byte-prefix constants for STAS v1, v2, STAS 3.0 (stas3-freeze-multisig) script identification. Extracted from TS `script-samples.ts`.
- `read_locking_script(script: &[u8]) -> ParsedScript`:
  - Match against known templates to determine `ScriptType`
  - For STAS: extract owner hash, token ID
  - For DSTAS: extract owner, redemption PKH, flags, frozen bit, action data (raw + parsed), service fields, optional data
  - For P2PKH/OpReturn: basic classification
  - Unknown scripts → `ScriptType::Unknown`
- `is_stas(script: &[u8]) -> bool` — quick classifier without full parse

**Key types:**
```rust
/// Result of parsing a locking script into its component fields.
pub struct ParsedScript {
    pub script_type: ScriptType,
    pub stas: Option<StasFields>,
    pub dstas: Option<DstasFields>,
}

/// Fields extracted from a STAS locking script.
pub struct StasFields {
    pub owner_hash: [u8; 20],
    pub token_id: TokenId,
}

/// Fields extracted from a DSTAS locking script.
pub struct DstasFields {
    pub owner: [u8; 20],
    pub redemption: [u8; 20],
    pub flags: Vec<u8>,
    pub action_data_raw: Option<Vec<u8>>,
    pub action_data_parsed: Option<ActionData>,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    pub frozen: bool,
}
```

**Tests:**
- Classify known STAS v1/v2/v3 script hex samples → correct ScriptType
- Parse DSTAS script → extract all fields correctly
- `is_stas()` returns true for STAS scripts, false for P2PKH/OpReturn/Unknown
- Unknown scripts → `ScriptType::Unknown` (no panic)
- Fuzz: arbitrary bytes → no panic, always returns a valid ParsedScript

**Acceptance:** Reader correctly classifies all sample scripts from TS `script-samples.ts`.

---

### Phase T3: Script Builders

**Scope:** `script/stas_builder.rs`, `script/dstas_builder.rs`
**Effort:** 2–3 days
**Dependencies:** T1, T2

**Deliverables:**
- `build_stas_locking_script(scheme: &TokenScheme, satoshis: u64, owner: &Address) -> Script`
  - Constructs a STAS v3 locking script from token parameters
- `build_dstas_locking_script(params: &DstasLockingParams) -> Script`
  - Constructs a DSTAS (stas3-freeze-multisig) locking script with all fields
- `build_dstas_flags(freezable: bool) -> Vec<u8>` — encode flags byte
- `derive_service_fields(scheme: &TokenScheme) -> Vec<Vec<u8>>` — authority key hash derivation
- Multisig owner preimage construction: m + [0x21 || pubkey]... + n → hash160

**Key type:**
```rust
/// Parameters for constructing a DSTAS locking script.
pub struct DstasLockingParams {
    /// Owner's public key hash (single key) or multisig preimage hash.
    pub owner: [u8; 20],
    /// Optional action data (swap offers, custom payloads).
    pub action_data: Option<ActionData>,
    /// Redemption public key hash (issuer's hash160 = token_id).
    pub redemption_pkh: [u8; 20],
    /// Whether this output is currently frozen.
    pub frozen: bool,
    /// Flags byte encoding capabilities (e.g., freezable).
    pub flags: Vec<u8>,
    /// Authority key hashes for freeze governance.
    pub service_fields: Vec<Vec<u8>>,
    /// Additional protocol-specific data.
    pub optional_data: Vec<Vec<u8>>,
}
```

**Tests:**
- Build → Read roundtrip: construct a locking script, parse it back, verify all fields match
- Multisig owner: 2-of-3 keys → deterministic hash160
- Frozen flag: build with frozen=true → reader detects frozen=true
- Property test: arbitrary valid DstasLockingParams → build → read roundtrip preserves all fields

**Acceptance:** 100% roundtrip fidelity between builder and reader.

---

### Phase T4: Contract TX & STAS Transaction Factories

**Scope:** `factory/contract.rs`, `template/stas.rs`, `factory/stas.rs`
**Effort:** 3–4 days
**Dependencies:** T1–T3 + `bsv-transaction`

**Deliverables:**

**Unlocking script template:**
- `StasUnlockingTemplate` implementing `UnlockingScriptTemplate` for STAS spends
- Constructor: `unlock(private_key: PrivateKey, sighash_flag: Option<u32>) -> StasUnlockingTemplate`
- `sign()` computes sighash and produces `<sig> <pubkey>` unlocking script
- `estimate_length()` returns appropriate estimate for STAS unlocking scripts

**Standalone contract TX builder (`factory/contract.rs`):**
```rust
/// Configuration for building a contract transaction.
///
/// The contract TX embeds the TokenScheme as an OP_RETURN output,
/// establishing the on-chain identity of the token.
pub struct ContractConfig {
    /// The token scheme to embed in the contract.
    pub scheme: TokenScheme,
    /// Funding UTXO to pay for the transaction.
    pub funding: Payment,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Build a standalone contract transaction.
///
/// Creates an OP_RETURN output containing the TokenScheme JSON/bytes.
/// Input: funding P2PKH. Outputs: P2PKH (contract value) + OP_RETURN (0 sats) + change.
pub fn build_contract_tx(config: &ContractConfig) -> Result<Transaction, TokenError>;
```

**STAS transaction factories (pure functions, no I/O):**

```rust
/// Configuration for issuing new STAS tokens.
pub struct IssueConfig {
    /// The token scheme defining this token.
    pub scheme: TokenScheme,
    /// Funding UTXO (issuer's address must match scheme.token_id).
    pub funding: Payment,
    /// Total satoshis to lock in the token output.
    pub satoshis: u64,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Configuration for transferring a STAS token to a new owner.
pub struct TransferConfig {
    /// The STAS UTXO to spend.
    pub token_input: Payment,
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Destination address and amount.
    pub destination: Destination,
    /// Optional OP_RETURN note to attach.
    pub note: Option<Vec<u8>>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Configuration for splitting a STAS token into multiple outputs.
pub struct SplitConfig {
    /// The STAS UTXO to split.
    pub token_input: Payment,
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Destination outputs (1–4). Satoshis must sum to input amount.
    pub destinations: Vec<Destination>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Configuration for merging two STAS UTXOs into one.
pub struct MergeConfig {
    /// First STAS UTXO (must have same owner as second).
    pub token_input_a: Payment,
    /// Second STAS UTXO (must have same owner as first).
    pub token_input_b: Payment,
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Destination address for the merged output.
    pub destination: Destination,
    /// Optional second destination for a split remainder.
    pub split_destination: Option<Destination>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Configuration for redeeming (burning) a STAS token back to P2PKH.
pub struct RedeemConfig {
    /// The STAS UTXO to redeem.
    pub token_input: Payment,
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Satoshis to redeem (must be ≥ 1).
    pub redeem_satoshis: u64,
    /// Optional STAS split destinations (≤ 3) for partial redemption.
    pub split_destinations: Vec<Destination>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}
```

**Factory functions:**
- `build_issue_tx(config: &IssueConfig) -> Result<Transaction, TokenError>`
  - 1 funding input → 1 STAS output + fee change
  - Validates: issuer address hash160 == scheme.token_id
- `build_transfer_tx(config: &TransferConfig) -> Result<Transaction, TokenError>`
  - 1 STAS input + 1 fee input → 1 STAS output + fee change + optional OP_RETURN note
- `build_split_tx(config: &SplitConfig) -> Result<Transaction, TokenError>`
  - 1 STAS input + 1 fee input → 1–4 STAS outputs + fee change
  - Validates: output satoshis sum == input satoshis (token conservation)
  - Validates: 1 ≤ destinations ≤ 4
  - Validates: token scheme allows splitting
- `build_merge_tx(config: &MergeConfig) -> Result<Transaction, TokenError>`
  - 2 STAS inputs (same owner) + 1 fee input → 1 STAS output + optional split dest + fee change
  - Validates: both inputs same owner address
  - Validates: output satoshis == sum of input satoshis
- `build_redeem_tx(config: &RedeemConfig) -> Result<Transaction, TokenError>`
  - 1 STAS input + 1 fee input → 1 P2PKH output (to issuer) + optional split STAS outputs
  - Validates: STAS input owner == redeem address (issuer)
  - Validates: ≤ 3 split destinations
  - Validates: redeem amount ≥ 1 satoshi

**Tests:**
- Contract TX: verify OP_RETURN output contains scheme bytes
- Each factory: construct tx, parse it back, verify input/output structure
- Amount conservation: input sats == output sats (for token outputs)
- Split validation: non-splittable token → `TokenError::NotSplittable`
- Validation errors: wrong owner for redeem, >4 split destinations, amount mismatch
- Golden vectors: build same transactions as TS SDK tests, compare raw tx hex byte-for-byte
- Property test: random valid amounts through split → merge → verify conservation

**Acceptance:** All factories produce valid transactions; golden vector tests pass against TS reference output.

---

### Phase T5: DSTAS Transaction Factories

**Scope:** `template/dstas.rs`, `factory/dstas.rs`
**Effort:** 4–5 days
**Dependencies:** T1–T4

**Deliverables:**

**Unlocking script template:**
- `DstasUnlockingTemplate` implementing `UnlockingScriptTemplate` with configurable `DstasSpendType`

**Config structs and factory functions:**

```rust
/// Configuration for issuing DSTAS tokens (two-transaction flow).
pub struct DstasIssueConfig {
    /// The token scheme defining this token.
    pub scheme: TokenScheme,
    /// Funding UTXO (must cover total token satoshis + fees).
    pub funding: Payment,
    /// Per-output token amounts and locking params.
    pub outputs: Vec<DstasDestination>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Result of a DSTAS issuance (two chained transactions).
pub struct DstasIssueTxs {
    /// Contract TX: funding → P2PKH (with scheme data) + fee change.
    pub contract_tx: Transaction,
    /// Issue TX: contract output → N DSTAS outputs + fee change.
    pub issue_tx: Transaction,
}

/// Configuration for a generic DSTAS spend transaction.
pub struct DstasBaseConfig {
    /// STAS token inputs (1–2). If 2, merge mode is used.
    pub token_inputs: Vec<Payment>,
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Destination outputs with DSTAS locking params.
    pub destinations: Vec<DstasDestination>,
    /// Spend type for unlocking script encoding.
    pub spend_type: DstasSpendType,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}

/// Configuration for a DSTAS swap flow transaction.
pub struct DstasSwapConfig {
    /// Exactly 2 STAS inputs for the swap.
    pub token_inputs: [Payment; 2],
    /// Funding UTXO for transaction fees.
    pub fee_input: Payment,
    /// Destination outputs.
    pub destinations: Vec<DstasDestination>,
    /// Optional manual mode override. If None, auto-detect from action_data.
    pub mode_override: Option<DstasSpendType>,
    /// Fee rate in satoshis per byte.
    pub fee_rate: u64,
}
```

**Transaction factories:**
- `build_dstas_issue_txs(config: &DstasIssueConfig) -> Result<DstasIssueTxs, TokenError>`
  - **Two-transaction flow:**
    1. Contract TX: funding → P2PKH (with scheme bytes in data push) + fee change
    2. Issue TX: contract output + fee change → N DSTAS outputs + fee change
  - Returns both transactions
  - Validates: funding > total token satoshis, issuer hash160 == scheme.token_id

- `build_dstas_base_tx(config: &DstasBaseConfig) -> Result<Transaction, TokenError>`
  - Generic DSTAS spend: 1–2 STAS inputs + 1 fee input → N DSTAS outputs + fee change
  - Supports configurable spend_type
  - If 2 inputs → merge mode (both marked as merge inputs)
  - Validates: ≤ 2 STAS inputs, ≥ 1 destination, input sats == output sats

- `build_dstas_freeze_tx(config: &DstasBaseConfig) -> Result<Transaction, TokenError>` — wrapper around base_tx with spend_type=2
- `build_dstas_unfreeze_tx(config: &DstasBaseConfig) -> Result<Transaction, TokenError>` — wrapper around base_tx with spend_type=2
- `build_dstas_swap_flow_tx(config: &DstasSwapConfig) -> Result<Transaction, TokenError>`
  - Exactly 2 STAS inputs
  - Auto-detect mode: if both inputs have swap action_data → swap-swap (type=4), else transfer-swap (type=1)
  - Manual mode override available via `mode_override`

**Tests:**
- Issue flow: contract TX output feeds issue TX input correctly (txid chaining)
- Freeze: output script has frozen=true; unfreeze: frozen=false
- Swap mode detection: mock scripts with/without swap action data
- Spend type encoding: verify unlocking script carries correct type byte
- Golden vectors against TS SDK where available

**Acceptance:** All DSTAS operations produce valid transactions with correct spend types and script fields.

---

### Phase T6: Bundle Factory (Feature-Gated)

**Scope:** `bundle/` module, behind `feature = "bundle"`
**Effort:** 5–7 days
**Dependencies:** T1–T5 + `bsv-wallet`

**Deliverables:**

**UTXO planner (`planner.rs`):**
- `plan_operations(available: &[OutPoint], targets: &[Destination]) -> Vec<PlannedOp>`
- Operations: `Merge(a, b)`, `Split(source, amounts)`, `Transfer(source, dest)`
- Algorithm:
  1. Sort available UTXOs descending by satoshis
  2. Greedily assign UTXOs to targets
  3. If no single UTXO covers a target → plan merges (pairwise, iterative)
  4. If a UTXO exceeds target → plan split
  5. Output: ordered list of operations where each op's outputs feed subsequent ops

**Bundle factories:**
```rust
/// Factory for constructing multi-transaction DSTAS token operations.
///
/// Generic over async callbacks for UTXO fetching and transaction lookup,
/// allowing consumers to plug in their own indexer/backend.
pub struct DstasBundleFactory<F, G, H, L, U>
where
    F: Fn(FundingRequest) -> impl Future<Output = Result<OutPoint, TokenError>>,
    G: Fn(u64) -> impl Future<Output = Result<Vec<OutPoint>, TokenError>>,
    H: Fn(&[String]) -> impl Future<Output = Result<HashMap<String, Transaction>, TokenError>>,
    L: Fn(LockingParamsRequest) -> DstasLockingParams,
    U: Fn(UnlockingRequest) -> Result<Script, TokenError>,
{ ... }
```

- `StasBundleFactory` — simpler variant for non-divisible STAS
- `DstasBundleFactory` — full variant with freeze/swap support
- Both expose:
  - `async fn transfer(&self, req) -> Result<PayoutBundle, TokenError>`
  - `PayoutBundle { transactions: Vec<Transaction>, fee_satoshis: u64 }`

**Tests:**
- Planner unit tests: various UTXO sets × target amounts → correct operation sequences
- Mock UTXO provider: in-memory UTXO set that the factory queries
- End-to-end: factory produces chain of valid transactions where outputs feed next inputs
- Edge cases: exact match (no merge/split needed), single UTXO, many small UTXOs requiring cascading merges
- Property test: random UTXO sets and targets → total satoshis conserved across all planned ops

**Acceptance:** Bundle factory produces correct multi-tx chains; all intermediate outputs are valid inputs to subsequent transactions.

---

## 8. Integration & Facade

After T6, update the `bsv-sdk` facade crate.

**Files to modify:**

| File | Change |
|------|--------|
| `Cargo.toml` (workspace root) | Add `"crates/bsv-tokens"` to `members`, add `bsv-tokens = { path = "crates/bsv-tokens" }` to `[workspace.dependencies]` |
| `bsv-sdk/Cargo.toml` | Add `bsv-tokens = { workspace = true }` dependency |
| `bsv-sdk/src/lib.rs` | Add `pub use bsv_tokens as tokens;` re-export |

```rust
// bsv-sdk/src/lib.rs
pub use bsv_tokens as tokens;
```

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    # ... existing ...
    "crates/bsv-tokens",
]

[workspace.dependencies]
bsv-tokens = { path = "crates/bsv-tokens" }
```

## 9. Test Strategy Summary

| Layer | Method | Coverage Target |
|-------|--------|----------------|
| Types | Unit | Serialization roundtrip (binary + JSON), validation |
| TokenId | Unit | Address parsing, PKH extraction |
| Scripts | Unit + Fuzz | Build↔read roundtrip, `is_stas()` classification, no panics on arbitrary input |
| Factories | Unit + Golden vectors | Structure validation, byte-exact match with TS SDK |
| Planner | Unit + Property | Operation correctness, satoshi conservation |
| Bundle | Integration + Mock | Multi-tx chain validity, edge cases |

**Golden vector extraction:** Clone the TS repo, run its test suite, capture raw tx hex outputs. Use these as reference vectors in Rust integration tests.

## 10. Timeline Estimate

| Phase | Effort | Cumulative |
|-------|--------|------------|
| T1: Foundation types | 1–2 days | 1–2 days |
| T2: Script reader | 2–3 days | 3–5 days |
| T3: Script builders | 2–3 days | 5–8 days |
| T4: Contract + STAS factories | 3–4 days | 8–12 days |
| T5: DSTAS factories | 4–5 days | 12–17 days |
| T6: Bundle factory | 5–7 days | 17–24 days |
| Integration + polish | 2–3 days | 19–27 days |
| **Total** | | **~4–5 weeks** |

## 11. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| STAS script template undocumented beyond TS source | Medium | Extract byte patterns directly from `script-samples.ts`; validate against on-chain data |
| TS SDK may have bugs we'd faithfully reproduce | Low | Cross-reference with STAS protocol spec if available; test against live chain data |
| Transaction builder API mismatch | Medium | May need to extend `bsv-transaction` builder with STAS-specific output methods; scope this during T3 |
| Bundle planner edge cases | High | Property-based testing with proptest; review TS implementation carefully for implicit assumptions |
| Config struct proliferation | Low | Keep configs co-located with their factory functions; use shared field types (`Payment`, `Destination`) to reduce duplication |

## 12. Verification Checklist

1. `cargo build --workspace` — compiles without errors
2. `cargo test --workspace` — all tests pass (existing + new)
3. `cargo clippy --workspace -- -D warnings` — no warnings
4. `cargo fmt --all -- --check` — formatted correctly
5. `cargo doc --no-deps -p bsv-tokens` — all public items documented
6. Verify `bsv_sdk::tokens::*` re-exports work from the facade crate

## 13. Future Work (Out of Scope)

- STAS token indexer / UTXO tracker
- ARC/mAPI broadcast integration
- Token metadata standards (BRC-48 etc.)
- Multi-token atomic swaps across different token IDs
- WASM bindings for the token crate
- Non-STAS token protocols (BRC-20, Run, etc.)

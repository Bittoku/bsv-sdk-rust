# PRD: `bsv-tokens` — STAS Token Support for bsv-sdk-rust

**Author:** HAL9000  
**Date:** 2026-02-15  
**Status:** Draft — Awaiting Review  
**Reference:** [dxs-stas-sdk](https://github.com/dxsapp/dxs-stas-sdk) (TypeScript)  
**Architecture:** [stas-architecture.md](./stas-architecture.md)

---

## 1. Goal

Add a `bsv-tokens` crate to the BSV Rust SDK that enables creation, transfer, and management of STAS and STAS3 tokens on the BSV blockchain. The crate builds on top of the existing SDK primitives (keys, scripts, transactions, wallets) and provides both low-level script construction and high-level transaction orchestration.

## 2. Non-Goals

- On-chain indexing or UTXO tracking (consumers provide their own backend)
- Network broadcasting (consumers handle submission to miners/ARC)
- GUI or CLI tooling
- Support for non-STAS token protocols (BRC-20, Run, etc.)

## 3. Design Decisions (Resolved)

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Async strategy for bundle factory | Generic `Fn` bounds returning `impl Future` | Avoids `async-trait` dep; consistent with existing transport traits in SDK |
| 2 | Signing abstraction | Use existing `UnlockingScriptTemplate` trait from `bsv-transaction` | Already defined and implemented for P2PKH; extend with STAS/STAS3 template impls |
| 3 | Script template versions | Build STAS 3.0 only, read v1/v2/STAS 3.0 | STAS 3.0 (stas3-freeze-multisig) is current; reader should classify legacy outputs found on-chain |
| 4 | WASM compatibility | Core crate is `no_std + alloc`; bundle factory behind `feature = "bundle"` requiring `std` | Clean boundary; bundle is the only module needing async I/O |

## 4. Crate Layout

```
crates/bsv-tokens/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── error.rs                # TokenError with thiserror
    ├── scheme.rs               # TokenScheme, Authority
    ├── script_type.rs          # ScriptType enum
    ├── types.rs                # Payment, Destination, SpendType, ActionData
    │
    ├── script/
    │   ├── mod.rs
    │   ├── templates.rs        # Byte-pattern constants for v1/v2/v3 classification
    │   ├── reader.rs           # read_locking_script() → ParsedScript
    │   ├── stas_builder.rs     # build_stas_locking_script()
    │   └── stas3_builder.rs    # build_stas3_locking_script(), flags, service fields
    │
    ├── template/
    │   ├── mod.rs
    │   ├── stas.rs             # UnlockingScriptTemplate impl for STAS spends
    │   └── stas3.rs            # UnlockingScriptTemplate impl for STAS3 spends (with spend_type)
    │
    ├── factory/
    │   ├── mod.rs
    │   ├── stas.rs             # STAS tx builders: issue, transfer, split, merge, redeem
    │   └── stas3.rs            # STAS3 tx builders: issue, base, freeze, unfreeze, swap flow
    │
    └── bundle/                 # Behind feature = "bundle"
        ├── mod.rs
        ├── planner.rs          # UTXO merge/split planning algorithm
        ├── stas_bundle.rs      # StasBundleFactory
        └── stas3_bundle.rs     # Stas3BundleFactory
```

## 5. Dependencies

```toml
[dependencies]
bsv-primitives = { workspace = true }
bsv-script = { workspace = true }
bsv-transaction = { workspace = true }
thiserror = { workspace = true }

[dependencies.bsv-wallet]
workspace = true
optional = true

[features]
default = []
bundle = ["bsv-wallet"]        # Enables bundle factories (requires std + async)
```

## 6. Implementation Plan

### Phase T1: Foundation Types
**Scope:** `error.rs`, `scheme.rs`, `script_type.rs`, `types.rs`  
**Effort:** 1–2 days  
**Dependencies:** `bsv-primitives` only

**Deliverables:**
- `TokenError` enum with variants: `InvalidScheme`, `AmountMismatch`, `InvalidScript`, `InvalidDestination`, `InvalidAuthority`, `SigningFailed`, `BundleError(String)`
- `TokenScheme` struct with `to_bytes()` / `from_bytes()` serialization (embeds in contract TX OP_RETURN)
- `Authority` struct for multisig freeze governance (m-of-n threshold + compressed pubkeys)
- `ScriptType` enum: `P2pkh`, `Stas`, `StasV2`, `Stas3`, `OpReturn`, `Unknown`
- `Payment` struct wrapping an `OutPoint` + signing key reference
- `Destination` struct: satoshis + address
- `Stas3Destination`: satoshis + `Stas3LockingParams`
- `Stas3SpendType` enum: `Transfer = 1`, `FreezeUnfreeze = 2`, `Swap = 4`
- `ActionData` enum: `Swap { ... }`, `Custom(Vec<u8>)`

**Tests:**
- TokenScheme roundtrip serialization (to_bytes → from_bytes)
- Authority validation (m ≤ n, key lengths = 33 bytes)
- ScriptType Display/Debug

**Acceptance:** `cargo test -p bsv-tokens` passes, all types compile against `no_std + alloc`.

---

### Phase T2: Script Reader & Templates
**Scope:** `script/templates.rs`, `script/reader.rs`  
**Effort:** 2–3 days  
**Dependencies:** T1 + `bsv-script`

**Deliverables:**
- `templates.rs`: Byte-prefix constants for STAS v1, v2, STAS 3.0 (stas3-freeze-multisig) script identification. Extracted from TS `script-samples.ts`.
- `read_locking_script(script: &[u8]) -> ParsedScript`:
  - Match against known templates to determine `ScriptType`
  - For STAS: extract owner hash, token ID
  - For STAS3: extract owner, redemption PKH, flags, frozen bit, action data (raw + parsed), service fields, optional data
  - For P2PKH/OpReturn: basic classification
  - Unknown scripts → `ScriptType::Unknown`

**Key type:**
```rust
pub struct ParsedScript {
    pub script_type: ScriptType,
    pub stas: Option<StasFields>,
    pub stas3: Option<Stas3Fields>,
}
```

**Tests:**
- Classify known STAS v1/v2/v3 script hex samples → correct ScriptType
- Parse STAS3 script → extract all fields correctly
- Unknown scripts → `ScriptType::Unknown` (no panic)
- Fuzz: arbitrary bytes → no panic, always returns a valid ParsedScript

**Acceptance:** Reader correctly classifies all sample scripts from TS `script-samples.ts`.

---

### Phase T3: Script Builders
**Scope:** `script/stas_builder.rs`, `script/stas3_builder.rs`  
**Effort:** 2–3 days  
**Dependencies:** T1, T2

**Deliverables:**
- `build_stas_locking_script(scheme: &TokenScheme, satoshis: u64, owner: &Address) -> Script`
  - Constructs a STAS v3 locking script from token parameters
- `build_stas3_locking_script(params: &Stas3LockingParams) -> Script`
  - Constructs a STAS3 (stas3-freeze-multisig) locking script with all fields
- `build_stas3_flags(freezable: bool) -> Vec<u8>` — encode flags byte
- `derive_service_fields(scheme: &TokenScheme) -> Vec<Vec<u8>>` — authority key hash derivation
- Multisig owner preimage construction: m + [0x21 || pubkey]... + n → hash160

**Tests:**
- Build → Read roundtrip: construct a locking script, parse it back, verify all fields match
- Multisig owner: 2-of-3 keys → deterministic hash160
- Frozen flag: build with frozen=true → reader detects frozen=true
- Property test: arbitrary valid Stas3LockingParams → build → read roundtrip preserves all fields

**Acceptance:** 100% roundtrip fidelity between builder and reader.

---

### Phase T4: STAS Transaction Factories
**Scope:** `template/stas.rs`, `factory/stas.rs`  
**Effort:** 3–4 days  
**Dependencies:** T1–T3 + `bsv-transaction`

**Deliverables:**

**Unlocking script template:**
- `StasUnlockingTemplate` implementing `UnlockingScriptTemplate` for STAS spends

**Transaction factories (pure functions, no I/O):**
- `build_stas_issue_tx(req) -> Result<Vec<u8>, TokenError>`
  - 1 funding input → 1 STAS output + fee change
  - Validates: issuer address hash160 == scheme.token_id
- `build_transfer_tx(req) -> Result<Vec<u8>, TokenError>`
  - 1 STAS input + 1 fee input → 1 STAS output + fee change + optional OP_RETURN note
- `build_split_tx(req) -> Result<Vec<u8>, TokenError>`
  - 1 STAS input + 1 fee input → 1–4 STAS outputs + fee change
  - Validates: output satoshis sum == input satoshis (token conservation)
  - Validates: 1 ≤ destinations ≤ 4
- `build_merge_tx(req) -> Result<Vec<u8>, TokenError>`
  - 2 STAS inputs (same owner) + 1 fee input → 1 STAS output + optional split dest + fee change
  - Validates: both inputs same owner address
  - Validates: output satoshis == sum of input satoshis
- `build_redeem_tx(req) -> Result<Vec<u8>, TokenError>`
  - 1 STAS input + 1 fee input → 1 P2PKH output (to issuer) + optional split STAS outputs
  - Validates: STAS input owner == redeem address (issuer)
  - Validates: ≤ 3 split destinations
  - Validates: redeem amount ≥ 1 satoshi

**Tests:**
- Each factory: construct tx, parse it back, verify input/output structure
- Amount conservation: input sats == output sats (for token outputs)
- Validation errors: wrong owner for redeem, >4 split destinations, amount mismatch
- Golden vectors: build same transactions as TS SDK tests, compare raw tx hex byte-for-byte
- Property test: random valid amounts through split → merge → verify conservation

**Acceptance:** All factories produce valid transactions; golden vector tests pass against TS reference output.

---

### Phase T5: STAS3 Transaction Factories
**Scope:** `template/stas3.rs`, `factory/stas3.rs`  
**Effort:** 4–5 days  
**Dependencies:** T1–T4

**Deliverables:**

**Unlocking script template:**
- `Stas3UnlockingTemplate` implementing `UnlockingScriptTemplate` with configurable `Stas3SpendType`

**Transaction factories:**
- `build_stas3_issue_txs(req) -> Result<Stas3IssueTxs, TokenError>`
  - **Two-transaction flow:**
    1. Contract TX: funding → P2PKH (with scheme bytes in data push) + fee change
    2. Issue TX: contract output + fee change → N STAS3 outputs + fee change
  - Returns both raw tx bytes
  - Validates: funding > total token satoshis, issuer hash160 == scheme.token_id

- `build_stas3_base_tx(req) -> Result<Vec<u8>, TokenError>`
  - Generic STAS3 spend: 1–2 STAS inputs + 1 fee input → N STAS3 outputs + fee change
  - Supports configurable spend_type
  - If 2 inputs → merge mode (both marked as merge inputs)
  - Validates: ≤ 2 STAS inputs, ≥ 1 destination, input sats == output sats

- `build_stas3_freeze_tx(req)` — wrapper around base_tx with spend_type=2
- `build_stas3_unfreeze_tx(req)` — wrapper around base_tx with spend_type=2
- `build_stas3_swap_flow_tx(req) -> Result<Vec<u8>, TokenError>`
  - Exactly 2 STAS inputs
  - Auto-detect mode: if both inputs have swap action_data → swap-swap (type=4), else transfer-swap (type=1)
  - Manual mode override available

**Tests:**
- Issue flow: contract TX output feeds issue TX input correctly (txid chaining)
- Freeze: output script has frozen=true; unfreeze: frozen=false
- Swap mode detection: mock scripts with/without swap action data
- Spend type encoding: verify unlocking script carries correct type byte
- Golden vectors against TS SDK where available

**Acceptance:** All STAS3 operations produce valid transactions with correct spend types and script fields.

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
pub struct Stas3BundleFactory<F, G, H, L, U>
where
    F: Fn(FundingRequest) -> impl Future<Output = Result<OutPoint, TokenError>>,
    G: Fn(u64) -> impl Future<Output = Result<Vec<OutPoint>, TokenError>>,
    H: Fn(&[String]) -> impl Future<Output = Result<HashMap<String, Transaction>, TokenError>>,
    L: Fn(LockingParamsRequest) -> Stas3LockingParams,
    U: Fn(UnlockingRequest) -> Result<Script, TokenError>,
{ ... }
```

- `StasBundleFactory` — simpler variant for non-divisible STAS
- `Stas3BundleFactory` — full variant with freeze/swap support
- Both expose:
  - `async fn transfer(&self, req) -> Result<PayoutBundle, TokenError>`
  - `PayoutBundle { transactions: Vec<Vec<u8>>, fee_satoshis: u64 }`

**Tests:**
- Planner unit tests: various UTXO sets × target amounts → correct operation sequences
- Mock UTXO provider: in-memory UTXO set that the factory queries
- End-to-end: factory produces chain of valid transactions where outputs feed next inputs
- Edge cases: exact match (no merge/split needed), single UTXO, many small UTXOs requiring cascading merges
- Property test: random UTXO sets and targets → total satoshis conserved across all planned ops

**Acceptance:** Bundle factory produces correct multi-tx chains; all intermediate outputs are valid inputs to subsequent transactions.

---

## 7. Integration & Facade

After T6, update the `bsv-sdk` facade crate:

```rust
// bsv-sdk/src/lib.rs
pub use bsv_tokens as tokens;
```

Add `bsv-tokens` to workspace `Cargo.toml`:
```toml
[workspace]
members = [
    # ... existing ...
    "crates/bsv-tokens",
]

[workspace.dependencies]
bsv-tokens = { path = "crates/bsv-tokens" }
```

## 8. Test Strategy Summary

| Layer | Method | Coverage Target |
|-------|--------|----------------|
| Types | Unit | Serialization roundtrip, validation |
| Scripts | Unit + Fuzz | Build↔read roundtrip, no panics on arbitrary input |
| Factories | Unit + Golden vectors | Structure validation, byte-exact match with TS SDK |
| Planner | Unit + Property | Operation correctness, satoshi conservation |
| Bundle | Integration + Mock | Multi-tx chain validity, edge cases |

**Golden vector extraction:** Clone the TS repo, run its test suite, capture raw tx hex outputs. Use these as reference vectors in Rust integration tests.

## 9. Timeline Estimate

| Phase | Effort | Cumulative |
|-------|--------|------------|
| T1: Foundation types | 1–2 days | 1–2 days |
| T2: Script reader | 2–3 days | 3–5 days |
| T3: Script builders | 2–3 days | 5–8 days |
| T4: STAS factories | 3–4 days | 8–12 days |
| T5: STAS3 factories | 4–5 days | 12–17 days |
| T6: Bundle factory | 5–7 days | 17–24 days |
| Integration + polish | 2–3 days | 19–27 days |
| **Total** | | **~4–5 weeks** |

## 10. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| STAS script template undocumented beyond TS source | Medium | Extract byte patterns directly from `script-samples.ts`; validate against on-chain data |
| TS SDK may have bugs we'd faithfully reproduce | Low | Cross-reference with STAS protocol spec if available; test against live chain data |
| Transaction builder API mismatch | Medium | May need to extend `bsv-transaction` builder with STAS-specific output methods; scope this during T3 |
| Bundle planner edge cases | High | Property-based testing with proptest; review TS implementation carefully for implicit assumptions |

## 11. Future Work (Out of Scope)

- STAS token indexer / UTXO tracker
- ARC/mAPI broadcast integration
- Token metadata standards (BRC-48 etc.)
- Multi-token atomic swaps across different token IDs
- WASM bindings for the token crate

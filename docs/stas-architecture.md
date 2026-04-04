# STAS Token Crate — Architecture Plan

## Overview

A new `bsv-tokens` crate providing STAS and STAS3 (Divisible STAS) token support,
built on top of the existing `bsv-primitives`, `bsv-script`, and `bsv-transaction` crates.

Source reference: [dxs-stas-sdk](https://github.com/dxsapp/dxs-stas-sdk) (TypeScript)

## Crate Structure

```
crates/bsv-tokens/
├── Cargo.toml
└── src/
    ├── lib.rs                  # Public API re-exports
    ├── scheme.rs               # TokenScheme definition
    ├── script_type.rs          # ScriptType enum (P2PKH, STAS, STAS3, OpReturn, Unknown)
    │
    ├── script/
    │   ├── mod.rs
    │   ├── stas_builder.rs     # Build STAS locking scripts from token params
    │   ├── stas3_builder.rs    # Build STAS3 (stas3-freeze-multisig) locking scripts
    │   ├── reader.rs           # Parse/classify locking scripts → ScriptType + parsed fields
    │   └── templates.rs        # Known STAS/STAS3 script template byte patterns
    │
    ├── factory/
    │   ├── mod.rs
    │   ├── stas.rs             # STAS tx factories: issue, transfer, split, merge, redeem
    │   ├── stas3.rs            # STAS3 tx factories: issue, transfer, freeze, unfreeze, swap
    │   └── bundle.rs           # Bundle factory: automatic merge/split/transfer planning
    │
    └── types.rs                # Shared types: OutPoint wrapper, Payment, Destination, SpendType
```

## Module Details

### 1. `scheme.rs` — Token Scheme

```rust
pub struct TokenScheme {
    pub name: String,
    pub token_id: [u8; 20],     // issuer's Hash160
    pub symbol: String,
    pub version: u8,
    pub divisible: bool,        // STAS vs STAS3
    pub freeze: bool,           // freeze/unfreeze capability
    pub authority: Option<Authority>,
}

pub struct Authority {
    pub m: u8,                  // multisig threshold
    pub public_keys: Vec<[u8; 33]>,
}

impl TokenScheme {
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(data: &[u8]) -> Result<Self, TokenError>;
}
```

Maps to TS: `TokenScheme` class in `src/bitcoin/token-scheme.ts`

### 2. `script_type.rs` — Script Classification

```rust
pub enum ScriptType {
    P2pkh,
    Stas,
    Dstas,
    OpReturn,
    Unknown,
}
```

Maps to TS: `ScriptType` enum in `src/bitcoin/script-type.ts`

### 3. `script/` — Script Build & Read

**`stas_builder.rs`** — Constructs STAS locking scripts from a `TokenScheme` + owner address.

**`stas3_builder.rs`** — Constructs STAS3 (stas3-freeze-multisig) locking scripts with:
- Owner hash (single or multisig preimage → hash160)
- Action data (swap offers, etc.)
- Redemption PKH (issuer's hash160 = token_id)
- Freeze flag
- Flags byte (freezable capability)
- Service fields (authority key hash for freeze governance)
- Optional data fields

```rust
pub struct DstasLockingParams {
    pub owner: [u8; 20],
    pub action_data: Option<ActionData>,
    pub redemption_pkh: [u8; 20],
    pub frozen: bool,
    pub flags: Vec<u8>,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
}

pub fn build_stas3_locking_script(params: &DstasLockingParams) -> Script;
```

Maps to TS: `src/script/build/stas3-freeze-multisig-builder.ts`, `src/script/build/script-builder.ts`

**`reader.rs`** — Parses a raw locking script and classifies it:

```rust
pub struct ParsedScript {
    pub script_type: ScriptType,
    pub stas: Option<StasFields>,
    pub stas3: Option<DstasFields>,
}

pub struct DstasFields {
    pub owner: [u8; 20],
    pub redemption: [u8; 20],
    pub flags: Vec<u8>,
    pub action_data_raw: Option<Vec<u8>>,
    pub action_data_parsed: Option<ActionDataKind>,
    pub service_fields: Vec<Vec<u8>>,
    pub optional_data: Vec<Vec<u8>>,
    pub frozen: bool,
}

pub fn read_locking_script(script: &[u8]) -> ParsedScript;
```

Maps to TS: `src/script/read/locking-script-reader.ts`

**`templates.rs`** — Known STAS/STAS3 script template byte prefixes for classification.

Maps to TS: `src/script/script-samples.ts`

### 4. `factory/stas.rs` — STAS Transaction Factories

Pure functions that compose transactions using `bsv-transaction`'s builder:

```rust
pub fn build_transfer_tx(req: &TransferRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_split_tx(req: &SplitRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_merge_tx(req: &MergeRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_redeem_tx(req: &RedeemRequest) -> Result<Vec<u8>, TokenError>;
```

**Key rules from TS source:**
- Transfer: 1 STAS input + 1 fee input → 1 STAS output + fee change + optional OP_RETURN note
- Split: 1 STAS input + 1 fee input → 1-4 STAS outputs (satoshis must balance) + fee change
- Merge: 2 STAS inputs (same owner) + 1 fee input → 1 STAS output + optional split + fee change
- Redeem: 1 STAS input + 1 fee input → 1 P2PKH output (to issuer) + optional split STAS outputs

Maps to TS: `src/transaction-factory.ts`

### 5. `factory/stas3.rs` — STAS3 Transaction Factories

More complex than STAS — supports spend types and multisig:

```rust
pub enum DstasSpendType {
    Transfer = 1,
    FreezeUnfreeze = 2,
    Swap = 4,
}

pub fn build_stas3_base_tx(req: &DstasBaseRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_stas3_issue_txs(req: &DstasIssueRequest) -> Result<DstasIssueTxs, TokenError>;
pub fn build_stas3_freeze_tx(req: &DstasBaseRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_stas3_unfreeze_tx(req: &DstasBaseRequest) -> Result<Vec<u8>, TokenError>;
pub fn build_stas3_swap_flow_tx(req: &DstasSwapFlowRequest) -> Result<Vec<u8>, TokenError>;
```

**STAS3 issue is a two-tx flow:**
1. **Contract TX**: funding UTXO → P2PKH output (with scheme metadata in OP_RETURN) + fee change
2. **Issue TX**: contract output + fee change → STAS3 token outputs + fee change

**Swap modes:**
- `transfer-swap`: one side uses spend_type=1, other consumed via swap matching
- `swap-swap`: both sides use spend_type=4
- Auto-detection based on action_data in locking scripts

Maps to TS: `src/stas3-factory.ts`

### 6. `factory/bundle.rs` — Bundle Factory (Batch Planning)

The most complex piece. Automatically plans multi-step UTXO management:

```rust
pub struct BundleFactory<F, G, H> {
    stas_wallet: Wallet,
    fee_wallet: Wallet,
    get_funding_utxo: F,    // async: fetch fee UTXO given estimated fee
    get_stas_utxo_set: G,   // async: fetch STAS UTXOs for wallet
    get_transactions: H,     // async: fetch raw txs by txid
    // + callbacks for locking params and unlocking script construction
}

pub struct PayoutBundle {
    pub transactions: Vec<Vec<u8>>,  // raw tx hex for each step
    pub fee_satoshis: u64,
}

impl BundleFactory {
    pub async fn transfer(&self, req: TransferRequest) -> Result<PayoutBundle, TokenError>;
}
```

**Planning algorithm (from TS `stas3-bundle-factory.ts`):**
1. Gather available STAS UTXOs from wallet
2. If total available < total needed → error
3. If UTXOs need consolidation → plan merge transactions (max 2 inputs per merge)
4. If a UTXO needs splitting → plan split transaction
5. Build final transfer transaction(s)
6. Chain outputs: each intermediate tx's outputs feed the next tx's inputs

This is generic over the UTXO provider — users supply async callbacks for fetching UTXOs and transactions from their indexer/backend.

Maps to TS: `src/stas3-bundle-factory.ts` (~600 lines), `src/stas-bundle-factory.ts` (~300 lines)

### 7. `types.rs` — Shared Types

```rust
pub struct Payment {
    pub outpoint: OutPoint,     // from bsv-transaction
    pub owner: SigningKey,      // PrivateKey or Wallet
}

pub struct Destination {
    pub satoshis: u64,
    pub address: Address,
}

pub struct DstasDestination {
    pub satoshis: u64,
    pub locking_params: DstasLockingParams,
}

pub enum ActionData {
    Swap { /* swap offer fields */ },
    Custom(Vec<u8>),
}
```

## Dependency Graph

```
bsv-tokens
├── bsv-primitives   (Address, Hash160, keys)
├── bsv-script       (Script type, opcodes)
├── bsv-transaction  (Transaction, TransactionBuilder)
└── bsv-wallet       (Wallet, key derivation)
```

## Integration with Workspace

Add to workspace `Cargo.toml`:
```toml
[workspace]
members = [
    # ... existing ...
    "crates/bsv-tokens",
]

[workspace.dependencies]
bsv-tokens = { path = "crates/bsv-tokens" }
```

Re-export from facade crate (`bsv-sdk`):
```rust
pub use bsv_tokens as tokens;
```

## Implementation Order

| Phase | Scope | Est. Effort |
|-------|-------|-------------|
| T1 | `scheme.rs`, `script_type.rs`, `types.rs` — core data types | Small |
| T2 | `script/templates.rs`, `script/reader.rs` — classify scripts | Medium |
| T3 | `script/stas_builder.rs`, `script/stas3_builder.rs` — build scripts | Medium |
| T4 | `factory/stas.rs` — STAS issue/transfer/split/merge/redeem | Medium |
| T5 | `factory/stas3.rs` — STAS3 issue/transfer/freeze/swap | Large |
| T6 | `factory/bundle.rs` — automatic batch planning (async) | Large |

T1–T4 are self-contained and testable in isolation.
T5 builds on T3 (STAS3 scripts).
T6 is the capstone — requires async runtime and external UTXO provider callbacks.

## Test Strategy

- **Unit tests**: Script build → read roundtrip; amount validation; scheme serialization
- **Integration tests**: Build known transactions, verify against TS SDK output (golden vectors)
- **Property tests**: Arbitrary token amounts through split/merge preserve satoshi balance
- **The TS repo has a `tests/` directory** — extract test vectors from there

## Open Questions

1. **Async runtime**: Bundle factory needs async for UTXO fetching. Use `async-trait` or generic `Future`?
2. **Signing abstraction**: TS uses `PrivateKey | Wallet`. Our `bsv-wallet` already has both — confirm API compatibility.
3. **Script template versioning**: STAS has evolved (stas, stas2, STAS 3.0). Which versions to support? The TS SDK focuses on STAS 3.0 (freeze-multisig). Start there.
4. **WASM compatibility**: Keep the crate `no_std`-compatible where possible for WASM target.

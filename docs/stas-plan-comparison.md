# STAS PRD Comparison: `bsv-tokens` (HAL9000) vs `bsv-stas` (Claude)

**Author:** CLU (Senior Architecture Review)
**Date:** 2026-02-16
**Status:** Final Assessment

---

## Overview

Two implementation plans were produced for adding STAS token support to `bsv-sdk-rust`. This document compares them and provides a final recommendation.

| | Plan 1: `bsv-tokens` | Plan 2: `bsv-stas` |
|---|---|---|
| **Author** | HAL9000 | Claude |
| **File** | `docs/stas-prd.md` | `docs/stas-prd-claude.md` |
| **Scope** | Full STAS + STAS3 + Bundle Factory | STAS-20 only |
| **Timeline** | 4–5 weeks (phased with estimates) | 8 steps (no estimates) |

---

## Common Ground

Both plans share the same fundamental design:

1. **Foundational types** — `TokenScheme`, error enums, script type classification
2. **Script layer** — locking script builder + reader/parser derived from TypeScript reference SDKs
3. **Unlocking template** — implements `UnlockingScriptTemplate` from `bsv-transaction`
4. **Transaction factories** — contract, issue, transfer, split, redeem
5. **Facade integration** — re-export from `bsv-sdk/src/lib.rs`
6. **Dependency chain** — `bsv-primitives`, `bsv-script`, `bsv-transaction`, `thiserror`
7. **Non-goals** — no indexer, no broadcast, no GUI

---

## Detailed Differences

### Scope & Protocol Coverage

| Capability | Plan 1 | Plan 2 |
|-----------|--------|--------|
| STAS-20 (fungible) | Yes | Yes |
| STAS3 (divisible, freeze, swap) | Full coverage | Deferred to "Phase 3" |
| Merge transaction | Included (Phase T4) | Deferred to "Phase 2" |
| Swap flow | Full (auto-detect swap-swap vs transfer-swap) | Not covered |
| Freeze / Unfreeze | Full with flags byte encoding | Not covered |
| Authority (m-of-n multisig governance) | Full `Authority` struct | Not covered |
| Bundle factory (multi-tx orchestration) | Full with UTXO planner algorithm | Not covered |
| Script version handling | Build v3, read v1/v2/v3 | No version awareness |

### Architecture & Design

| Aspect | Plan 1 | Plan 2 |
|--------|--------|--------|
| **Crate name** | `bsv-tokens` (generic, extensible) | `bsv-stas` (protocol-specific) |
| **`no_std` / WASM** | Explicit `no_std + alloc` core, `std` behind feature gate | Not addressed |
| **Async strategy** | Resolved: generic `Fn` bounds, avoids `async-trait` | Not addressed |
| **Design decisions** | 4 resolved decisions documented with rationale | None documented |
| **File organization** | Grouped by concern: `script/`, `template/`, `factory/`, `bundle/` | Flat: one file per tx type (`transfer.rs`, `split.rs`) |
| **Feature gates** | `bundle` feature requiring `bsv-wallet` + `std` | None |

### Testing & Verification

| Approach | Plan 1 | Plan 2 |
|----------|--------|--------|
| Unit tests | Yes | Yes |
| Fuzz testing | Yes (arbitrary bytes → no panic) | No |
| Property-based testing | Yes (proptest for satoshi conservation) | No |
| Golden vectors | Yes (byte-exact match with TS SDK output) | No |
| Integration tests with mocks | Yes (mock UTXO provider) | No |
| Layered test strategy table | Yes | No |

### Risk Management

| | Plan 1 | Plan 2 |
|---|---|---|
| Risk register | 4 risks with severity + mitigation | None |
| Script research | Resolved upfront (extract from `script-samples.ts`) | Deferred to implementation time |

### Plan 2 Unique Strengths

- **`*Config` struct pattern** explicitly documented for factory functions (e.g., `ContractConfig`, `IssueConfig`, `TransferConfig`) — good API ergonomics
- **Standalone `build_contract_tx()`** — useful as independent public API
- **`#![deny(missing_docs)]`** — enforces documentation at compile time
- **`serde` / `serde_json`** dependencies for `TokenScheme` JSON serialization
- **Explicit "Files to Modify" table** — clear about workspace integration changes
- **"Critical Existing Files to Reference"** — helpful for implementor orientation

---

## Config Struct Pattern Assessment

The `*Config` struct pattern proposed by Plan 2 is **idiomatic Rust**, not a Go-ism. The existing SDK already uses both patterns appropriately:

- **Direct parameters** for simple functions: `p2pkh::lock(address)`, `p2pkh::unlock(key, flag)`
- **Config structs** for complex configuration: `interpreter::Config`

STAS factory functions require 4–8 parameters (funding UTXO, token inputs, destinations, scheme, keys, fee rate, etc.), making Config structs the natural choice. Benefits include:

- `#[derive(Default)]` for optional fields
- `..Default::default()` struct update syntax (Rust-specific ergonomic win)
- Named fields prevent argument-order bugs
- Easy to extend without breaking API

**Recommendation:** Use Config structs for all factory functions. Keep direct parameters for simple operations (lock/unlock equivalents).

---

## Architect Seniority Assessment

**Plan 1 demonstrates significantly more architectural maturity:**

1. **Completeness** — tackles the full protocol surface including the hardest parts (STAS3, freeze governance, swap detection, bundle planning) rather than deferring them
2. **Architectural rigor** — `no_std`/WASM boundaries, async strategy, feature gating show production deployment awareness
3. **Testing depth** — fuzz, property-based, golden vectors, and layered strategy vs. standard unit tests only
4. **Risk awareness** — identifies undocumented script templates, potential TS SDK bugs, and high-severity planner edge cases
5. **Naming foresight** — `bsv-tokens` anticipates future token protocol support without premature coupling

Plan 2 is a competent implementation guide for STAS-20 specifically, with good attention to API consistency and developer ergonomics, but it reads as a "first milestone" plan rather than a complete architectural vision.

---

## Final Recommendation

**Implement Plan 1 as the primary plan**, incorporating the following from Plan 2:

### Adopt from Plan 2

1. **`*Config` structs** for all factory function signatures — idiomatic Rust, better ergonomics than raw parameter lists
2. **Standalone `build_contract_tx()`** as additional public API alongside the STAS3 2-tx issue flow
3. **`#![deny(missing_docs)]`** at crate root
4. **`serde` / `serde_json`** for `TokenScheme` JSON serialization
5. **"Critical Existing Files to Reference"** section as implementor guide

### Keep from Plan 1

Everything else — the full STAS + STAS3 + Bundle scope, `no_std` design, async strategy, v1/v2/v3 script handling, fuzz + property testing, golden vectors, risk register, and `bsv-tokens` crate naming.

### Implementation Order

Follow Plan 1's phased approach (T1 → T6) but use Plan 2's Config struct pattern for all factory APIs starting from Phase T4.

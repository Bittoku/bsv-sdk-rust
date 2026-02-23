# Security Audit Report — BSV SDK Rust

**Date**: 2026-02-23
**Scope**: Full workspace (11 crates)
**Tools**: `cargo audit` (926 advisories), `cargo clippy`, manual code review

---

## Executive Summary

| Category | Result |
|----------|--------|
| Known CVEs in dependencies | **0 vulnerabilities** (291 crate dependencies scanned) |
| Unsafe code blocks | **0** (no `unsafe` in any source file) |
| Clippy warnings | **3** (all minor style, no security impact) |
| Manual review findings | **3 Critical, 1 High, 5 Medium** |

---

## Dependency Audit (`cargo audit`)

Scanned 291 crate dependencies against 926 RustSec advisories.
**Result: No known vulnerabilities found.**

---

## Critical Findings

### CRITICAL-1: VarInt Parser Panics on Truncated Input

**File**: `crates/bsv-primitives/src/util/mod.rs:34-54`

`VarInt::from_bytes()` directly indexes into the input slice without bounds checking. A malicious peer sending a truncated VarInt prefix (e.g. `0xff` with fewer than 8 following bytes) will cause an index-out-of-bounds panic, crashing the application.

**Impact**: Remote Denial of Service — any network peer can crash a node.

**Recommendation**: Return `Result<(Self, usize), ParseError>` with explicit length checks before each indexing operation.

---

### CRITICAL-2: PrivateKey `Clone` Creates Unzeroized Copies

**File**: `crates/bsv-primitives/src/ec/private_key.rs:21`

`PrivateKey` derives `Clone`, which creates byte-for-byte copies of the signing key. While `Drop` zeroizes the original, cloned copies are not zeroized until the runtime drops them. This leaves private key material in memory indefinitely.

**Impact**: Private keys recoverable via memory inspection (cold boot, core dumps, swap).

**Recommendation**: Either remove `Clone` or implement a custom `Clone` that immediately zeroizes intermediate byte arrays.

---

### CRITICAL-3: KeyDeriver `Clone` Propagates Unzeroized Root Key

**File**: `crates/bsv-wallet/src/key_deriver.rs:23-35`

`KeyDeriver` derives `Clone` and contains a `PrivateKey` (root key). Cloning creates unzeroized copies of the root key, compounding CRITICAL-2.

**Impact**: Root key compromise — all derived keys are at risk.

**Recommendation**: Remove `Clone` from `KeyDeriver` or use `Arc<PrivateKey>` for shared access.

---

## High Severity

### HIGH-1: Regex Compiled with `unwrap()` at Runtime

**File**: `crates/bsv-wallet/src/key_deriver.rs:17-18`

A `LazyLock` regex uses `.unwrap()`. While the hardcoded pattern is valid, any future modification could cause a panic.

**Recommendation**: Use `.expect("static regex is valid")` for clarity, or replace the regex with a simple character-class loop.

---

## Medium Severity

| ID | Issue | File | Recommendation |
|----|-------|------|----------------|
| MED-1 | `hex::decode(VERSION).unwrap()` on constant | `crates/bsv-message/src/encrypted.rs:38` | Use a byte literal constant instead |
| MED-2 | Derived `Debug` on `PrivateKey` may leak key material in logs/panics | `crates/bsv-primitives/src/ec/private_key.rs:21` | Custom `Debug` impl that prints `[REDACTED]` |
| MED-3 | `PartialEq` for `PrivateKey` uses non-constant-time comparison | `crates/bsv-primitives/src/ec/private_key.rs:307-313` | Use `subtle::ConstantTimeEq` |
| MED-4 | Verbose protocol validation errors reveal exact rules | `crates/bsv-wallet/src/key_deriver.rs:209-243` | Use generic error messages in release builds |
| MED-5 | Key ID length limit (800 chars) may allow resource exhaustion | `crates/bsv-wallet/src/key_deriver.rs:196-206` | Consider tighter bounds or total-length cap |

---

## Positive Findings

- **No unsafe code** anywhere in the workspace
- **OsRng** used correctly for all cryptographic randomness
- **Zeroization** infrastructure properly applied (via `zeroize` crate)
- **Comprehensive input validation** on all public API boundaries (key parsing, WIF, DER signatures, checksums)
- **All `unwrap()` calls** in the codebase are confined to `#[cfg(test)]` modules

---

## Clippy Warnings (Non-Security)

1. `needless_borrow` in `crates/bsv-tokens/src/lineage.rs:149`
2. `type_complexity` in `crates/bsv-tokens/src/proof.rs:29`
3. `manual_range_contains` in `crates/bsv-tokens/src/script/stas_btg_builder.rs:559`

---

## Remediation Priority

1. **Immediate** — Fix CRITICAL-1 (VarInt DoS), CRITICAL-2 & CRITICAL-3 (key zeroization)
2. **Before release** — Fix MED-2 (Debug leak), MED-3 (timing attack)
3. **Consider** — Address remaining Medium issues and clippy warnings

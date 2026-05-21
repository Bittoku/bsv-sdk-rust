# Changelog

## v0.4.0 — 2026-05-21

### ⚠ BREAKING CHANGES

- **STAS 3.0 base template swapped to the canonical v0.1 / spec v0.2.3
  engine.** The stale 2812-byte template in `STAS3_BASE_TEMPLATE_HEX` has
  been replaced with the 2899-byte engine from
  `github.com/stassso/STAS-3-script-templates` (SHA-256
  `5c659f5f3abdad612c4bfd19b6034f2df0c0bcef1af1ca928d0f5a34ac3ee371`).
  `STAS3_BASE_TEMPLATE_LEN` is bumped 2812 → 2899. Transactions built
  against the old template are not compatible; rebuild and re-sign with
  the new SDK before broadcasting (620e126).
- **§9.5 piece-array encoder rewritten to option-3 wire format.** Each
  piece is now emitted as a separate `OP_PUSHDATA` with `piece_count`
  encoded as a minimal numeric opcode (`OP_1`..`OP_16`) per DXS's
  `ScriptBuilder.addNumber` convention. The prior length-prefixed
  byte-stream encoder is gone; the 127-byte per-piece limit is removed
  (the engine reads pieces via `OP_PUSHDATA` directly, so larger pieces
  are now valid) (620e126).
- **Swap-swap factory witness layout DXS-aligned.** The trailing
  piece-array block now occupies the slot-18 (txType) position in the
  unlocking script per DXS's `prepareMergeInfo` shape:
  `[counterparty_vout, piece_1..piece_N, piece_count,
  counterparty_asset_tail, 1]`. Required for the canonical engine's
  back-to-genesis hash check to pass (e8bd923, 505cbaa).

### Bug Fixes

- **STAS 3.0 swap-swap engine_verify now passes.** Layered fixes:
  prepended (not appended) trailing-piece block, full DXS-aligned
  witness layout, corrected swap-descriptor test data
  (`requested_pkh` = destination owner; `requested_script_hash` =
  SHA256(counterparty asset_tail)). 273/273 tests green including
  `engine_accepts_swap_swap_with_trailing_pieces` (505cbaa).
- Cross-SDK pin test re-enabled against the new canonical template;
  byte-identical Rust ↔ Elixir output verified (620e126).
- Exact-fee no-change-leg transfer test bumped 1602 → 1646 sats to
  account for the 87-byte-longer canonical template (+44 sat fee at
  rate 500) (620e126).

### Internal / Chores

- Swap-swap engine_verify integration test uses deterministic 32-byte
  private keys, enabling byte-diff debugging across SDK boundaries
  (e93bc1e).

## v0.3.2 — 2026-05-17

<!--
  v0.3.1 was tagged locally but never released: a prior partial release
  had already published the bittoku-bsv facade at 0.3.1 (members lagged
  at 0.3.0), so 0.3.1 could not be re-published. v0.3.2 reconciles the
  whole workspace — all member crates and the facade — to one version.
-->


### Bug Fixes

- **STAS 3.0 piece-length limit corrected to 127 bytes** — the §9.5 piece-array
  encoder previously allowed pieces up to 255 bytes, but the on-chain v0.1
  engine reads each piece's 1-byte length prefix via `OP_1 OP_SPLIT` as a
  *signed* script-num, so any length ≥ 128 reads as negative and `OP_SPLIT`
  rejects it. The encoder now hard-errors at >127 bytes for both the swap and
  merge paths instead of silently producing unspendable transactions (1e6ce19).

### Internal / Chores

- Cross-SDK piece-array fixture test pins the §9.5 merge encoding byte-for-byte
  against the matching `bsv_sdk_elixir` test (46e2090).
- The lineage validator is now documented as experimental — it does not handle
  STAS 3.0 ancestors or model the issuance-set invariant (46e2090).
- Added the missing factory config re-exports (confiscate / merge / redeem /
  split) to the crate root; corrected an inaccurate "crate-private" comment
  (1e6ce19).
- Workspace version reconciled to 0.3.1 across all member crates and the
  `bittoku-bsv` facade.

## v0.3.0 — 2026-05-01

### New Features

- **STAS 3.0 end-to-end engine verification** — full preimage-to-script execution
  test pipeline so STAS 3.0 transactions are validated against the real BSV
  script interpreter before broadcast (6685cac).
- **§7 unlock-witness auto-wiring** — every STAS 3.0 factory now constructs the
  §7 unlock witness automatically; callers no longer have to hand-build it
  (8910b82).
- **§9.5 trailing piece-array** — atomic-swap factories emit the trailing
  piece-array block required by STAS 3.0 §9.5 (139d115).

### Bug Fixes

- **§10.3 no-auth path** — preserve the real BIP-143 preimage in slot 19 when
  the no-auth path is taken; the previous build was zero-padding the slot,
  which broke verification (8fca2bf).
- **STAS 3.0 piece-array framing** — the piece-array is length-prefixed, not
  space-delimited; correcting this fixes parsing on the consumer side
  (7d62dc1).

### Maintenance

- `cargo fmt --all` applied across the workspace; CI fmt step now passes (44f886f).
- Local `pre-commit` hook installed to enforce `cargo fmt --all -- --check`
  before every commit, matching the CI gate.

## v0.2.0 — 2026-03-26

### New Features

- **P2MPKH (Pay-to-Multiple-Public-Key-Hash)** — m-of-n multisig ownership for STAS/STAS3 tokens
  - `MultisigScript`: construct, serialize, parse, mpkh (HASH160), lock/unlock
  - `SigningKey` enum: `Single(PrivateKey)` | `Multi { private_keys, multisig }`
  - `OwnerAddress` enum: `Address(Address)` | `Mpkh([u8;20])`
  - `StasMpkhUnlockingTemplate`: produces `<sig1>…<sigM> <multisig_script>`
  - `Stas3MpkhUnlockingTemplate`: same pattern with `Stas3SpendType`
  - `unlock_from_signing_key()`: single dispatch for factories
  - All STAS/STAS3 factories auto-dispatch P2PKH vs P2MPKH
  - BTG factories reject P2MPKH with clear error (not yet supported)

- **STAS3 Full Operations**
  - Split, merge, confiscation, and redeem operations
  - Transfer-swap, swap-swap modes with remainder legs and frozen rejection
  - `Stas3BundleFactory`: automatic merge/split/transfer planning

### Security

- Vulnerability remediation from comprehensive audit

### Maintenance

- crates.io metadata: repository URL fix, optional transports
- `#![deny(missing_docs)]` enforced across all crates

### Test Coverage

- 519 tests, 0 failures
- 22 new P2MPKH integration tests covering template signing, factory integration, and BTG rejection

## v0.1.0

- Initial release — BSV SDK with primitives, script, transaction, wallet, message, auth, SPV, tokens (STAS/STAS3/BTG), transports (ARC, JungleBus)

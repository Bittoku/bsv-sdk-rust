# Changelog

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

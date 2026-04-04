# Changelog

## v0.2.0 — 2026-03-26

### New Features

- **P2MPKH (Pay-to-Multiple-Public-Key-Hash)** — m-of-n multisig ownership for STAS/STAS3 tokens
  - `MultisigScript`: construct, serialize, parse, mpkh (HASH160), lock/unlock
  - `SigningKey` enum: `Single(PrivateKey)` | `Multi { private_keys, multisig }`
  - `OwnerAddress` enum: `Address(Address)` | `Mpkh([u8;20])`
  - `StasMpkhUnlockingTemplate`: produces `<sig1>…<sigM> <multisig_script>`
  - `DstasMpkhUnlockingTemplate`: same pattern with `DstasSpendType`
  - `unlock_from_signing_key()`: single dispatch for factories
  - All STAS/STAS3 factories auto-dispatch P2PKH vs P2MPKH
  - BTG factories reject P2MPKH with clear error (not yet supported)

- **STAS3 Full Operations**
  - Split, merge, confiscation, and redeem operations
  - Transfer-swap, swap-swap modes with remainder legs and frozen rejection
  - `DstasBundleFactory`: automatic merge/split/transfer planning

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

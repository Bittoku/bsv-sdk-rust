# bittoku-bsv

A comprehensive BSV Blockchain SDK for Rust. Facade crate that re-exports every component of the
[`bsv-sdk-rust`](https://github.com/Bittoku/bsv-sdk-rust) workspace under one name.

Cryptographic primitives, transaction building, script interpretation, wallet operations,
authenticated messaging, SPV verification, and STAS token templates — all in one dependency.

## Install

```bash
cargo add bittoku-bsv
```

Or in `Cargo.toml`:

```toml
[dependencies]
bittoku-bsv = "0.3"
```

Enable optional transports (ARC broadcaster, JungleBus indexer):

```toml
[dependencies]
bittoku-bsv = { version = "0.3", features = ["transports"] }
```

## What's included

The crate re-exports the following modules:

| Module | Underlying crate | Purpose |
|--------|------------------|---------|
| `primitives` | `bsv-primitives` | Hash, EC keys (secp256k1), Base58, AES-256-GCM, BRC-42 key derivation |
| `script` | `bsv-script` | Script parsing, opcodes, addresses, full script interpreter |
| `transaction` | `bsv-transaction` | Transaction building, sighash (BIP-143 FORKID), P2PKH templates |
| `wallet` | `bsv-wallet` | 29-method wallet interface, BRC-42/43 derivation, ProtoWallet, wire protocol |
| `message` | `bsv-message` | BRC-78 ECIES encryption, BRC-77 message signing |
| `auth` | `bsv-auth` | Peer authentication, sessions, BRC-31 identity certificates |
| `spv` | `bsv-spv` | Merkle path verification (BRC-74), BEEF format (BRC-64/95/96) |
| `tokens` | `bsv-tokens` | STAS token templates (Gen2, 3.0), bundle factory, P2MPKH |
| `arc` | `bsv-arc` | ARC broadcaster client *(feature: `transports`)* |
| `junglebus` | `bsv-junglebus` | JungleBus indexer client *(feature: `transports`)* |

## Quick start

### Sign a P2PKH transaction

```rust
use bittoku_bsv::primitives::ec::private_key::PrivateKey;
use bittoku_bsv::transaction::transaction::Transaction;
use bittoku_bsv::transaction::template::p2pkh;

let key = PrivateKey::from_wif("L3...")?;
let mut tx = Transaction::new();
// ... add inputs and outputs ...
p2pkh::sign(&mut tx, 0, &key)?;
```

### Encrypt a message (BRC-78)

```rust
use bittoku_bsv::primitives::ec::private_key::PrivateKey;
use bittoku_bsv::message::encrypted::{encrypt, decrypt};

let sender_key = PrivateKey::from_wif("L3...")?;
let recipient_pub = recipient_key.pub_key();

let ciphertext = encrypt(b"Hello, BSV!", &sender_key, &recipient_pub)?;
let plaintext  = decrypt(&ciphertext, &recipient_key)?;
```

### Wallet key derivation (BRC-42)

```rust
use bittoku_bsv::wallet::{ProtoWallet, WalletInterface};
use bittoku_bsv::wallet::types::*;

let wallet = ProtoWallet::from_private_key(key)?;
let result = wallet.get_public_key(GetPublicKeyArgs {
    encryption_args: EncryptionArgs {
        protocol_id: Protocol { security_level: 0, protocol: "myapp".into() },
        key_id: "user-123".into(),
        counterparty: Counterparty { r#type: CounterpartyType::Self_, counterparty: None },
        ..Default::default()
    },
    identity_key: false,
    for_self: None,
})?;
```

### STAS token transfer

```rust
use bittoku_bsv::tokens::factory::transfer;
// See the workspace docs for full STAS Gen2 / 3.0 examples.
```

## Standards implemented

| BRC | Description |
|-----|-------------|
| BRC-31 | Identity certificates |
| BRC-42 | Key derivation protocol |
| BRC-43 | Invoice numbering |
| BRC-64 | BEEF transaction format |
| BRC-74 | Merkle path format (BUMP) |
| BRC-77 | Message signing |
| BRC-78 | Message encryption (ECIES) |
| BRC-95/96 | BEEF extensions |

Plus the [STAS token protocol](https://stastoken.com) Gen2 and 3.0 templates with full P2MPKH
support, bundle factories, and provenance verification.

## Origin

Ported from the [Go BSV SDK](https://github.com/bsv-blockchain/go-sdk) with idiomatic Rust patterns
and equivalent test coverage. All test vectors match the Go and TypeScript SDKs byte-for-byte.

## Repository

Full source, individual crate documentation, and contribution guide:
<https://github.com/Bittoku/bsv-sdk-rust>

## License

[MIT](https://github.com/Bittoku/bsv-sdk-rust/blob/main/LICENSE)

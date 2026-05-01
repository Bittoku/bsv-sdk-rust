# bsv-sdk-rust

A comprehensive BSV Blockchain SDK in Rust, providing cryptographic primitives, transaction building, script interpretation, wallet operations, authenticated messaging, and SPV verification.

Ported from the [Go BSV SDK](https://github.com/bsv-blockchain/go-sdk) with idiomatic Rust patterns and equivalent test coverage.

## Crates

| Crate | Description |
|-------|-------------|
| **bsv-primitives** | Hash functions, EC keys (secp256k1), Base58, AES-256-GCM, BRC-42 key derivation |
| **bsv-script** | Script parsing, opcodes, addresses, and a full script interpreter |
| **bsv-transaction** | Transaction building, sighash (BIP-143 FORKID), P2PKH templates |
| **bsv-wallet** | 29-method wallet interface, key derivation (BRC-42/43), ProtoWallet, wire protocol serializer |
| **bsv-message** | BRC-78 ECIES encryption/decryption, BRC-77 message signing/verification |
| **bsv-auth** | Peer authentication, session management, BRC-31 identity certificates |
| **bsv-spv** | Merkle path verification (BRC-74), BEEF transaction format (BRC-64/95/96) |
| **bsv-sdk** | Facade crate re-exporting all of the above |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
bsv-sdk = { path = "bsv-sdk" }
```

Or depend on individual crates for finer control:

```toml
[dependencies]
bsv-primitives = { path = "crates/bsv-primitives" }
bsv-transaction = { path = "crates/bsv-transaction" }
```

## Examples

### Create and Sign a P2PKH Transaction

```rust
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::template::p2pkh;

// Create a private key
let key = PrivateKey::from_wif("L3...")?;

// Build and sign a P2PKH transaction
let mut tx = Transaction::new();
// ... add inputs and outputs ...
p2pkh::sign(&mut tx, 0, &key)?;
```

### Encrypt a Message (BRC-78)

```rust
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_message::encrypted::{encrypt, decrypt};

let sender_key = PrivateKey::from_wif("L3...")?;
let recipient_pub = recipient_key.pub_key();

let ciphertext = encrypt(b"Hello, BSV!", &sender_key, &recipient_pub)?;
let plaintext = decrypt(&ciphertext, &recipient_key)?;
```

### Wallet Key Derivation (BRC-42)

```rust
use bsv_wallet::{KeyDeriver, ProtoWallet, WalletInterface};
use bsv_wallet::types::*;

let wallet = ProtoWallet::from_private_key(key)?;

// Derive a child key for a specific protocol
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

## Development setup

After cloning, point git at the versioned hooks directory so `cargo fmt`
gets enforced before every commit (matching the CI fmt gate):

```bash
git config core.hooksPath .githooks
```

This only needs to be run once per clone.

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

All test vectors are ported from the Go SDK to ensure byte-for-byte compatibility.

## Architecture

```
bsv-sdk-rust/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── bsv-primitives/         # Hash, EC, Base58, AES, key derivation
│   ├── bsv-script/             # Script, opcodes, interpreter
│   ├── bsv-transaction/        # Transaction, sighash, P2PKH
│   ├── bsv-wallet/             # Wallet trait, ProtoWallet, serializer
│   ├── bsv-message/            # BRC-78 encrypt, BRC-77 sign
│   ├── bsv-auth/               # Peer auth, sessions, certificates
│   └── bsv-spv/                # Merkle paths, BEEF, chain tracker
└── bsv-sdk/                    # Facade re-exporting all crates
```

## Key Design Decisions

- **k256** for secp256k1 curve operations with a Bitcoin-specific layer on top
- **thiserror** for error types, **serde** for JSON serialization
- Manual binary serialization matching the Go/TypeScript SDK wire formats
- **tokio** only in auth/spv crates where async networking is needed
- WASM-compatible core crates via feature flags

## Standards Implemented

| BRC | Description | Crate |
|-----|-------------|-------|
| BRC-42 | Key derivation protocol | bsv-primitives, bsv-wallet |
| BRC-43 | Invoice numbering | bsv-wallet |
| BRC-31 | Identity certificates | bsv-auth |
| BRC-64 | BEEF transaction format | bsv-spv |
| BRC-74 | Merkle path format (BUMP) | bsv-spv |
| BRC-77 | Message signing | bsv-message |
| BRC-78 | Message encryption (ECIES) | bsv-message |
| BRC-95/96 | BEEF extensions | bsv-spv |

## License

[MIT](LICENSE)

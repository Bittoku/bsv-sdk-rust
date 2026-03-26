//! Common types for token operations.

use serde::{Deserialize, Serialize};

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_primitives::hash::hash160;
use bsv_script::{Address, Script};
use bsv_transaction::template::p2mpkh::MultisigScript;

/// Signing credentials for a UTXO — either a single key (P2PKH) or
/// threshold keys with a multisig script (P2MPKH).
#[derive(Clone, Debug)]
pub enum SigningKey {
    /// Single private key for standard P2PKH spending.
    Single(PrivateKey),
    /// Threshold private keys + full multisig script for P2MPKH spending.
    ///
    /// The number of private keys must equal `multisig.threshold()`.
    /// Keys must correspond to public keys in the multisig script in order.
    Multi {
        /// The m private keys used to satisfy the threshold.
        private_keys: Vec<PrivateKey>,
        /// The full m-of-n multisig script.
        multisig: MultisigScript,
    },
}

impl SigningKey {
    /// Convenience constructor for P2PKH signing.
    pub fn single(key: PrivateKey) -> Self {
        SigningKey::Single(key)
    }

    /// Convenience constructor for P2MPKH signing.
    pub fn multi(private_keys: Vec<PrivateKey>, multisig: MultisigScript) -> Self {
        SigningKey::Multi {
            private_keys,
            multisig,
        }
    }

    /// Get the 20-byte hash for this signing key.
    ///
    /// For P2PKH: HASH160 of the compressed public key.
    /// For P2MPKH: HASH160 of the serialized multisig script (the MPKH).
    pub fn hash160(&self) -> [u8; 20] {
        match self {
            SigningKey::Single(key) => hash160(&key.pub_key().to_compressed()),
            SigningKey::Multi { multisig, .. } => multisig.mpkh(),
        }
    }

    /// Returns `true` if this is a P2MPKH signing key.
    pub fn is_multi(&self) -> bool {
        matches!(self, SigningKey::Multi { .. })
    }
}

impl From<PrivateKey> for SigningKey {
    fn from(key: PrivateKey) -> Self {
        SigningKey::Single(key)
    }
}

/// A UTXO payment input for token transactions.
///
/// For P2PKH inputs (standard or funding), use `SigningKey::Single`.
/// For P2MPKH inputs (multisig-owned tokens), use `SigningKey::Multi`.
pub struct Payment {
    /// Transaction hash of the UTXO.
    pub txid: Hash,
    /// Output index within the transaction.
    pub vout: u32,
    /// Satoshi value of the UTXO.
    pub satoshis: u64,
    /// The locking script of the UTXO.
    pub locking_script: Script,
    /// Signing credentials for this input.
    pub signing_key: SigningKey,
}

/// Owner address for token destinations — either a standard address (P2PKH)
/// or a 20-byte MPKH (P2MPKH).
///
/// Both produce the same 20-byte hash in the locking script. The difference
/// is in how the unlocking script is constructed at spend time.
#[derive(Debug, Clone)]
pub enum OwnerAddress {
    /// Standard single-key address.
    Address(Address),
    /// Multisig script hash (MPKH). The 20-byte HASH160 of the multisig
    /// script, stored directly since no `Address` representation exists
    /// for P2MPKH.
    Mpkh([u8; 20]),
}

impl OwnerAddress {
    /// Get the 20-byte hash (PKH or MPKH).
    pub fn hash(&self) -> [u8; 20] {
        match self {
            OwnerAddress::Address(addr) => {
                let mut h = [0u8; 20];
                h.copy_from_slice(&addr.public_key_hash);
                h
            }
            OwnerAddress::Mpkh(mpkh) => *mpkh,
        }
    }
}

impl From<Address> for OwnerAddress {
    fn from(addr: Address) -> Self {
        OwnerAddress::Address(addr)
    }
}

impl From<[u8; 20]> for OwnerAddress {
    fn from(mpkh: [u8; 20]) -> Self {
        OwnerAddress::Mpkh(mpkh)
    }
}

impl From<&MultisigScript> for OwnerAddress {
    fn from(ms: &MultisigScript) -> Self {
        OwnerAddress::Mpkh(ms.mpkh())
    }
}

/// A destination for token transfer.
#[derive(Debug, Clone)]
pub struct Destination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount to send.
    pub satoshis: u64,
}

/// dSTAS spending operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DstasSpendType {
    /// Standard token transfer.
    Transfer = 1,
    /// Freeze or unfreeze operation.
    FreezeUnfreeze = 2,
    /// Confiscation by authority.
    Confiscation = 3,
    /// Cancel a pending swap.
    SwapCancellation = 4,
}

/// Additional data attached to a dSTAS action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionData {
    /// Atomic swap action data.
    ///
    /// Encoded as 61 bytes per leg: 1 (kind 0x01) + 32 (hash) + 20 (PKH) +
    /// 4 (numerator LE) + 4 (denominator LE).
    Swap {
        /// SHA-256 hash of the counterparty's locking script tail.
        requested_script_hash: [u8; 32],
        /// The 20-byte public key hash of the requested recipient.
        requested_pkh: [u8; 20],
        /// Exchange rate numerator (little-endian u32).
        rate_numerator: u32,
        /// Exchange rate denominator (little-endian u32).
        rate_denominator: u32,
    },
    /// Custom application data.
    Custom(Vec<u8>),
}

/// The detected swap mode for a two-input DSTAS transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstasSwapMode {
    /// One input is a regular transfer, the other is consumed via swap matching.
    TransferSwap,
    /// Both inputs have swap action data — atomic counter-swap.
    SwapSwap,
}

/// Parameters for constructing a dSTAS locking script.
#[derive(Debug, Clone)]
pub struct DstasLockingParams {
    /// The recipient address.
    pub address: Address,
    /// The spend type for this locking script.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}

/// A destination specific to dSTAS token operations.
#[derive(Debug, Clone)]
pub struct DstasDestination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount.
    pub satoshis: u64,
    /// The dSTAS spend type.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::PrivateKey;
    use bsv_transaction::template::p2mpkh::MultisigScript;

    #[test]
    fn signing_key_single_hash160() {
        let key = PrivateKey::new();
        let expected = hash160(&key.pub_key().to_compressed());
        let sk = SigningKey::Single(key);
        assert_eq!(sk.hash160(), expected);
    }

    #[test]
    fn signing_key_multi_hash160_is_mpkh() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let expected = ms.mpkh();
        let sk = SigningKey::Multi {
            private_keys: vec![keys[0].clone(), keys[1].clone()],
            multisig: ms,
        };
        assert_eq!(sk.hash160(), expected);
    }

    #[test]
    fn signing_key_is_multi() {
        let key = PrivateKey::new();
        assert!(!SigningKey::Single(key).is_multi());

        let keys: Vec<PrivateKey> = (0..2).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(1, pubs).unwrap();
        assert!(SigningKey::Multi {
            private_keys: vec![keys[0].clone()],
            multisig: ms,
        }
        .is_multi());
    }

    #[test]
    fn signing_key_from_private_key() {
        let key = PrivateKey::new();
        let sk: SigningKey = key.clone().into();
        assert!(!sk.is_multi());
        assert_eq!(sk.hash160(), hash160(&key.pub_key().to_compressed()));
    }

    #[test]
    fn owner_address_from_address() {
        let key = PrivateKey::new();
        let pkh = hash160(&key.pub_key().to_compressed());
        let addr = Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let oa = OwnerAddress::from(addr.clone());
        assert_eq!(oa.hash(), pkh);
    }

    #[test]
    fn owner_address_from_mpkh() {
        let mpkh = [0xab; 20];
        let oa = OwnerAddress::from(mpkh);
        assert_eq!(oa.hash(), mpkh);
    }

    #[test]
    fn owner_address_from_multisig_script() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let oa = OwnerAddress::from(&ms);
        assert_eq!(oa.hash(), ms.mpkh());
    }
}

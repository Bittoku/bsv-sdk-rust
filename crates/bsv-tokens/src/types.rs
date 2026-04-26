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

/// STAS 3.0 spending operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Stas3SpendType {
    /// Standard token transfer.
    Transfer = 1,
    /// Freeze or unfreeze operation.
    FreezeUnfreeze = 2,
    /// Confiscation by authority.
    Confiscation = 3,
    /// Cancel a pending swap.
    SwapCancellation = 4,
}

/// Additional data attached to a STAS 3.0 action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionData {
    /// Atomic swap action data.
    ///
    /// Encoded as a minimum of 61 bytes per leg:
    ///   1 (kind 0x01) + 32 (hash) + 20 (PKH) + 4 (numerator LE) + 4 (denominator LE)
    /// followed by an optional recursive `next` payload (spec §6.3).
    Swap {
        /// SHA-256 hash of the counterparty's locking script tail.
        requested_script_hash: [u8; 32],
        /// The 20-byte public key hash of the requested recipient.
        requested_pkh: [u8; 20],
        /// Exchange rate numerator (little-endian u32).
        rate_numerator: u32,
        /// Exchange rate denominator (little-endian u32).
        rate_denominator: u32,
        /// Optional `next` field — the var2 value to be installed on the
        /// maker's remainder UTXO after the swap is partially or fully
        /// consumed. `None` indicates no `next` field (terminal entry).
        #[doc(hidden)]
        next: Option<Box<NextVar2>>,
    },
    /// Custom application data.
    Custom(Vec<u8>),
}

/// Canonical typed swap descriptor for STAS 3.0 var2 (action byte 0x01).
///
/// Spec §6.3 — Fixed 61-byte minimum layout (1 + 32 + 20 + 4 + 4) followed
/// by an optional `next` field (recursive chained-swap form).
///
/// The encoder ([`SwapDescriptor::to_var2_bytes`]) produces the FULL var2
/// payload INCLUDING the leading `0x01` action byte. When `next` is a
/// nested swap, the inner descriptor is emitted WITHOUT a leading `0x01`
/// (per spec §6.3 — "Encoding is the same as the top-level descriptor,
/// minus including the leading action byte").
///
/// The 61-byte non-recursive form remains a valid input/output of the
/// parser/encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapDescriptor {
    /// SHA-256 hash of the counterparty's locking script tail.
    pub requested_script_hash: [u8; 32],
    /// HASH160 of the address/MPKH to which the counter-asset is delivered.
    pub receive_addr: [u8; 20],
    /// Exchange rate numerator (little-endian u32).
    pub rate_numerator: u32,
    /// Exchange rate denominator (little-endian u32).
    pub rate_denominator: u32,
    /// Optional recursive `next` field. `None` = no next field (terminal).
    pub next: Option<Box<NextVar2>>,
}

/// The recursive `next` discriminator inside a [`SwapDescriptor`] (spec §6.3).
///
/// `next`'s leading byte selects the form:
/// - `0x00` → [`NextVar2::Passive`] (action byte 0x00 + arbitrary bytes)
/// - `0x02` (single byte) → [`NextVar2::Frozen`] (frozen marker)
/// - any other → [`NextVar2::Swap`] inner descriptor minus its leading
///   `0x01` action byte
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextVar2 {
    /// Passive var2 — leading action byte `0x00` followed by arbitrary
    /// owner data (or empty).
    Passive(Vec<u8>),
    /// Frozen marker — single byte `0x02`.
    Frozen,
    /// Recursive swap descriptor.
    ///
    /// Encoded as the inner descriptor's fields WITHOUT a leading `0x01`
    /// (the action byte is implied — spec §6.3).
    Swap(SwapDescriptor),
}

/// Errors produced while parsing a STAS 3.0 swap descriptor (spec §6.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwapDescriptorError {
    /// Top-level swap descriptor missing the `0x01` action byte.
    #[error("missing action byte 0x01 at start of swap descriptor")]
    MissingActionByte,
    /// Buffer truncated before all required descriptor bytes were read.
    #[error("descriptor truncated at offset {0} (need at least {1} more bytes)")]
    Truncated(usize, usize),
    /// Unknown leading byte for `next` field.
    #[error("unknown next-form leading byte 0x{0:02x} at offset {1}")]
    UnknownNextForm(u8, usize),
    /// Extra bytes appeared after a `Frozen` (`0x02`) marker.
    #[error("trailing bytes after frozen marker (0x02)")]
    TrailingAfterFrozen,
}

impl SwapDescriptor {
    /// Encode this descriptor as a complete var2 payload INCLUDING the
    /// leading `0x01` action byte (spec §6.3).
    pub fn to_var2_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(61);
        out.push(0x01);
        self.append_body(&mut out);
        out
    }

    /// Append this descriptor's BODY (without leading `0x01`) into `out`,
    /// then recursively append any `next` payload.
    fn append_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.requested_script_hash);
        out.extend_from_slice(&self.receive_addr);
        out.extend_from_slice(&self.rate_numerator.to_le_bytes());
        out.extend_from_slice(&self.rate_denominator.to_le_bytes());
        if let Some(next) = &self.next {
            match next.as_ref() {
                NextVar2::Passive(bytes) => {
                    out.push(0x00);
                    out.extend_from_slice(bytes);
                }
                NextVar2::Frozen => {
                    out.push(0x02);
                }
                NextVar2::Swap(inner) => {
                    // Inner swap is emitted WITHOUT the leading 0x01 action byte
                    // (spec §6.3 — "minus including the leading action byte").
                    inner.append_body(out);
                }
            }
        }
    }

    /// Parse a complete top-level var2 payload (must start with `0x01`).
    ///
    /// The 61-byte non-recursive form is a valid input.
    pub fn parse(var2_bytes: &[u8]) -> Result<Self, SwapDescriptorError> {
        if var2_bytes.is_empty() || var2_bytes[0] != 0x01 {
            return Err(SwapDescriptorError::MissingActionByte);
        }
        let (descriptor, consumed) = Self::parse_body(var2_bytes, 1)?;
        if consumed != var2_bytes.len() {
            // The body parser already consumed every recognised next form,
            // so any leftover bytes here mean unknown trailing data.
            return Err(SwapDescriptorError::UnknownNextForm(
                var2_bytes[consumed],
                consumed,
            ));
        }
        Ok(descriptor)
    }

    /// Parse a descriptor body starting at `offset` (no leading action byte).
    /// Returns the descriptor and the offset past the last consumed byte.
    fn parse_body(
        bytes: &[u8],
        offset: usize,
    ) -> Result<(Self, usize), SwapDescriptorError> {
        const FIXED: usize = 32 + 20 + 4 + 4;
        if bytes.len() < offset + FIXED {
            return Err(SwapDescriptorError::Truncated(
                offset,
                offset + FIXED - bytes.len(),
            ));
        }
        let mut requested_script_hash = [0u8; 32];
        requested_script_hash.copy_from_slice(&bytes[offset..offset + 32]);
        let mut receive_addr = [0u8; 20];
        receive_addr.copy_from_slice(&bytes[offset + 32..offset + 52]);
        let rate_numerator = u32::from_le_bytes([
            bytes[offset + 52],
            bytes[offset + 53],
            bytes[offset + 54],
            bytes[offset + 55],
        ]);
        let rate_denominator = u32::from_le_bytes([
            bytes[offset + 56],
            bytes[offset + 57],
            bytes[offset + 58],
            bytes[offset + 59],
        ]);
        let mut cursor = offset + FIXED;

        let next = if cursor < bytes.len() {
            let (node, consumed) = parse_next(bytes, cursor)?;
            cursor = consumed;
            Some(Box::new(node))
        } else {
            None
        };

        Ok((
            SwapDescriptor {
                requested_script_hash,
                receive_addr,
                rate_numerator,
                rate_denominator,
                next,
            },
            cursor,
        ))
    }
}

/// Parse a `next` payload at `offset`, returning the node and the new cursor.
fn parse_next(bytes: &[u8], offset: usize) -> Result<(NextVar2, usize), SwapDescriptorError> {
    let head = bytes[offset];
    match head {
        0x00 => {
            // Passive — owner data follows the 0x00 action byte to end.
            let payload = bytes[offset + 1..].to_vec();
            Ok((NextVar2::Passive(payload), bytes.len()))
        }
        0x02 => {
            // Frozen — must be the only byte at this position.
            if offset + 1 != bytes.len() {
                return Err(SwapDescriptorError::TrailingAfterFrozen);
            }
            Ok((NextVar2::Frozen, bytes.len()))
        }
        _ => {
            // Inner swap descriptor: parse fields starting AT this offset
            // (no leading action byte to consume — spec §6.3).
            let (inner, consumed) = SwapDescriptor::parse_body(bytes, offset)?;
            Ok((NextVar2::Swap(inner), consumed))
        }
    }
}

/// Bidirectional conversion: from typed [`SwapDescriptor`] into the
/// pre-existing [`ActionData::Swap`] enum variant. The receive address is
/// stored as `requested_pkh` (the existing field name; semantics per spec
/// §6.3 = HASH160 of the recipient address/MPKH).
impl From<SwapDescriptor> for ActionData {
    fn from(d: SwapDescriptor) -> Self {
        ActionData::Swap {
            requested_script_hash: d.requested_script_hash,
            requested_pkh: d.receive_addr,
            rate_numerator: d.rate_numerator,
            rate_denominator: d.rate_denominator,
            next: d.next,
        }
    }
}

impl ActionData {
    /// Construct a swap [`ActionData`] from a typed [`SwapDescriptor`].
    pub fn from_swap_descriptor(d: SwapDescriptor) -> Self {
        d.into()
    }

    /// If this is a swap action, return its descriptor view.
    pub fn as_swap_descriptor(&self) -> Option<SwapDescriptor> {
        match self {
            ActionData::Swap {
                requested_script_hash,
                requested_pkh,
                rate_numerator,
                rate_denominator,
                next,
            } => Some(SwapDescriptor {
                requested_script_hash: *requested_script_hash,
                receive_addr: *requested_pkh,
                rate_numerator: *rate_numerator,
                rate_denominator: *rate_denominator,
                next: next.clone(),
            }),
            _ => None,
        }
    }
}

/// The detected swap mode for a two-input STAS3 transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stas3SwapMode {
    /// One input is a regular transfer, the other is consumed via swap matching.
    TransferSwap,
    /// Both inputs have swap action data — atomic counter-swap.
    SwapSwap,
}

/// Parameters for constructing a STAS 3.0 locking script.
#[derive(Debug, Clone)]
pub struct Stas3LockingParams {
    /// The recipient address.
    pub address: Address,
    /// The spend type for this locking script.
    pub spend_type: Stas3SpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}

/// A destination specific to STAS 3.0 token operations.
#[derive(Debug, Clone)]
pub struct Stas3Destination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount.
    pub satoshis: u64,
    /// The STAS 3.0 spend type.
    pub spend_type: Stas3SpendType,
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

    // -----------------------------------------------------------------
    // SwapDescriptor encoder/decoder (spec §6.3 — recursive `next`)
    // -----------------------------------------------------------------

    fn base_descriptor() -> SwapDescriptor {
        SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x41; 20],
            rate_numerator: 10,
            rate_denominator: 11,
            next: None,
        }
    }

    #[test]
    fn swap_descriptor_no_next_round_trip_61_bytes() {
        let d = base_descriptor();
        let bytes = d.to_var2_bytes();
        assert_eq!(bytes.len(), 61, "no-next descriptor must be 61 bytes");
        assert_eq!(bytes[0], 0x01);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn swap_descriptor_passive_empty_round_trip() {
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Passive(Vec::new())));
        let bytes = d.to_var2_bytes();
        // 61 + 1 (action 0x00) = 62 bytes.
        assert_eq!(bytes.len(), 62);
        assert_eq!(bytes[61], 0x00);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn swap_descriptor_passive_arbitrary_round_trip() {
        let payload: Vec<u8> = (0..16).collect();
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Passive(payload.clone())));
        let bytes = d.to_var2_bytes();
        assert_eq!(bytes.len(), 61 + 1 + payload.len());
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn swap_descriptor_frozen_round_trip() {
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Frozen));
        let bytes = d.to_var2_bytes();
        assert_eq!(bytes.len(), 62);
        assert_eq!(bytes[61], 0x02);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn swap_descriptor_one_level_recursive_round_trip() {
        let inner = SwapDescriptor {
            requested_script_hash: [0x22; 32],
            receive_addr: [0x42; 20],
            rate_numerator: 20,
            rate_denominator: 21,
            next: None,
        };
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Swap(inner)));
        let bytes = d.to_var2_bytes();
        // 61 (top) + 60 (inner body, no leading 0x01) = 121 bytes
        assert_eq!(bytes.len(), 121);
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn swap_descriptor_three_level_recursive_round_trip_and_snapshot() {
        // Innermost (level 3): no next.
        let l3 = SwapDescriptor {
            requested_script_hash: [0x33; 32],
            receive_addr: [0x43; 20],
            rate_numerator: 30,
            rate_denominator: 31,
            next: None,
        };
        // Level 2: next = Swap(l3)
        let l2 = SwapDescriptor {
            requested_script_hash: [0x22; 32],
            receive_addr: [0x42; 20],
            rate_numerator: 20,
            rate_denominator: 21,
            next: Some(Box::new(NextVar2::Swap(l3))),
        };
        // Level 1 (top): next = Swap(l2)
        let top = SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x41; 20],
            rate_numerator: 10,
            rate_denominator: 11,
            next: Some(Box::new(NextVar2::Swap(l2))),
        };
        let bytes = top.to_var2_bytes();
        assert_eq!(bytes.len(), 61 + 60 + 60); // 181
        // Pinned snapshot — independently computed; must round-trip and match.
        let expected_hex = "01\
1111111111111111111111111111111111111111111111111111111111111111\
4141414141414141414141414141414141414141\
0a000000\
0b000000\
2222222222222222222222222222222222222222222222222222222222222222\
4242424242424242424242424242424242424242\
14000000\
15000000\
3333333333333333333333333333333333333333333333333333333333333333\
4343434343434343434343434343434343434343\
1e000000\
1f000000";
        assert_eq!(hex::encode(&bytes), expected_hex.replace('\n', ""));
        let parsed = SwapDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, top);
    }

    #[test]
    fn swap_descriptor_rejects_truncated_inner_swap() {
        // Top-level descriptor with `next = Swap(...)` claimed but inner body
        // is short by 4 bytes (only 56 of expected 60 inner-body bytes).
        let mut bytes = SwapDescriptor {
            requested_script_hash: [0x11; 32],
            receive_addr: [0x41; 20],
            rate_numerator: 10,
            rate_denominator: 11,
            next: Some(Box::new(NextVar2::Swap(SwapDescriptor {
                requested_script_hash: [0x22; 32],
                receive_addr: [0x42; 20],
                rate_numerator: 20,
                rate_denominator: 21,
                next: None,
            }))),
        }
        .to_var2_bytes();
        bytes.truncate(bytes.len() - 4);
        assert!(matches!(
            SwapDescriptor::parse(&bytes),
            Err(SwapDescriptorError::Truncated(..))
        ));
    }

    #[test]
    fn swap_descriptor_rejects_trailing_after_frozen() {
        let mut d = base_descriptor();
        d.next = Some(Box::new(NextVar2::Frozen));
        let mut bytes = d.to_var2_bytes();
        bytes.push(0xAB); // illegal extra byte after 0x02 marker
        assert!(matches!(
            SwapDescriptor::parse(&bytes),
            Err(SwapDescriptorError::TrailingAfterFrozen)
        ));
    }

    #[test]
    fn swap_descriptor_rejects_missing_action_byte() {
        let body = base_descriptor().to_var2_bytes();
        // Strip leading 0x01 — parser must reject.
        assert!(matches!(
            SwapDescriptor::parse(&body[1..]),
            Err(SwapDescriptorError::MissingActionByte)
        ));
    }

    #[test]
    fn action_data_swap_round_trip_through_descriptor() {
        let d = SwapDescriptor {
            requested_script_hash: [0xab; 32],
            receive_addr: [0xcd; 20],
            rate_numerator: 5,
            rate_denominator: 7,
            next: Some(Box::new(NextVar2::Frozen)),
        };
        let action: ActionData = d.clone().into();
        let back = action.as_swap_descriptor().unwrap();
        assert_eq!(back, d);
    }
}

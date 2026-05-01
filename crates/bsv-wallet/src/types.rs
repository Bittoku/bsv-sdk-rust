//! Core wallet types — Protocol, Counterparty, SecurityLevel, EncryptionArgs, etc.

use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::signature::Signature;
use serde::{Deserialize, Serialize};

/// Security level for wallet operations.
pub type SecurityLevel = i32;

/// Silent security level — no user prompts required.
pub const SECURITY_LEVEL_SILENT: SecurityLevel = 0;
/// Prompt the user once per application.
pub const SECURITY_LEVEL_EVERY_APP: SecurityLevel = 1;
/// Prompt the user per application and per counterparty combination.
pub const SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY: SecurityLevel = 2;

/// Protocol identifier with security level and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protocol {
    /// The security level required by this protocol.
    pub security_level: SecurityLevel,
    /// The protocol name string (e.g. "BRC-42").
    pub protocol: String,
}

/// The type of counterparty in a cryptographic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CounterpartyType {
    /// Not yet specified (default state).
    #[default]
    Uninitialized,
    /// The "anyone" counterparty — no specific party.
    Anyone,
    /// The wallet owner themselves.
    Self_,
    /// A specific third-party identified by public key.
    Other,
}

/// Counterparty in a cryptographic operation.
#[derive(Debug, Clone)]
pub struct Counterparty {
    /// The type of counterparty relationship.
    pub r#type: CounterpartyType,
    /// The counterparty's public key, required when type is `Other`.
    pub counterparty: Option<PublicKey>,
}

impl Default for Counterparty {
    fn default() -> Self {
        Self {
            r#type: CounterpartyType::Uninitialized,
            counterparty: None,
        }
    }
}

/// Common parameters for cryptographic operations.
#[derive(Debug, Clone)]
pub struct EncryptionArgs {
    /// The protocol under which the key is derived.
    pub protocol_id: Protocol,
    /// An application-specific key identifier.
    pub key_id: String,
    /// The counterparty for the operation.
    pub counterparty: Counterparty,
    /// Whether this is a privileged operation requiring elevated access.
    pub privileged: bool,
    /// Human-readable reason for requesting privileged access.
    pub privileged_reason: String,
    /// Whether to prompt the user for permission.
    pub seek_permission: bool,
}

/// Arguments for encrypting data.
#[derive(Debug, Clone)]
pub struct EncryptArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The plaintext data to encrypt.
    pub plaintext: Vec<u8>,
}

/// Arguments for decrypting data.
#[derive(Debug, Clone)]
pub struct DecryptArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The ciphertext data to decrypt.
    pub ciphertext: Vec<u8>,
}

/// Result of an encryption operation.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// The encrypted ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

/// Result of a decryption operation.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    /// The decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Arguments for retrieving a public key.
#[derive(Debug, Clone)]
pub struct GetPublicKeyArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// If true, return the wallet's identity key instead of a derived key.
    pub identity_key: bool,
    /// If true, derive the key for self rather than the counterparty.
    pub for_self: Option<bool>,
}

/// Result of a public key retrieval.
#[derive(Debug, Clone)]
pub struct GetPublicKeyResult {
    /// The retrieved or derived public key.
    pub public_key: PublicKey,
}

/// Arguments for creating a digital signature.
#[derive(Debug, Clone)]
pub struct CreateSignatureArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The raw data to sign (will be SHA-256 hashed internally).
    pub data: Vec<u8>,
    /// A pre-computed 32-byte hash to sign directly (bypasses internal hashing).
    pub hash_to_directly_sign: Vec<u8>,
}

/// Result of a signature creation.
#[derive(Debug, Clone)]
pub struct CreateSignatureResult {
    /// The ECDSA signature.
    pub signature: Signature,
}

/// Arguments for verifying a digital signature.
#[derive(Debug, Clone)]
pub struct VerifySignatureArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The original data that was signed.
    pub data: Vec<u8>,
    /// A pre-computed 32-byte hash to verify directly.
    pub hash_to_directly_verify: Vec<u8>,
    /// The signature to verify.
    pub signature: Option<Signature>,
    /// If true, derive the verification key for self.
    pub for_self: Option<bool>,
}

/// Result of a signature verification.
#[derive(Debug, Clone)]
pub struct VerifySignatureResult {
    /// Whether the signature is valid.
    pub valid: bool,
}

/// Arguments for creating an HMAC.
#[derive(Debug, Clone)]
pub struct CreateHmacArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The data to compute the HMAC over.
    pub data: Vec<u8>,
}

/// Result of an HMAC creation.
#[derive(Debug, Clone)]
pub struct CreateHmacResult {
    /// The 32-byte SHA-256 HMAC.
    pub hmac: [u8; 32],
}

/// Arguments for verifying an HMAC.
#[derive(Debug, Clone)]
pub struct VerifyHmacArgs {
    /// Key derivation and counterparty parameters.
    pub encryption_args: EncryptionArgs,
    /// The data that the HMAC was computed over.
    pub data: Vec<u8>,
    /// The 32-byte HMAC to verify.
    pub hmac: [u8; 32],
}

/// Result of an HMAC verification.
#[derive(Debug, Clone)]
pub struct VerifyHmacResult {
    /// Whether the HMAC is valid.
    pub valid: bool,
}

// === Action / Transaction Types ===

/// Arguments for creating a transaction action.
#[derive(Debug, Clone)]
pub struct CreateActionArgs {
    /// Human-readable description of the action.
    pub description: String,
    /// BEEF-encoded input transaction data.
    pub input_beef: Vec<u8>,
    /// Transaction inputs to spend.
    pub inputs: Vec<CreateActionInput>,
    /// Transaction outputs to create.
    pub outputs: Vec<CreateActionOutput>,
    /// Optional transaction lock time.
    pub lock_time: Option<u32>,
    /// Optional transaction version number.
    pub version: Option<u32>,
    /// Labels to associate with this action.
    pub labels: Vec<String>,
}

/// A single input for a create-action request.
#[derive(Debug, Clone)]
pub struct CreateActionInput {
    /// The outpoint to spend (txid:vout format).
    pub outpoint: String,
    /// Human-readable description of this input.
    pub input_description: String,
    /// The unlocking script bytes.
    pub unlocking_script: Vec<u8>,
    /// Expected length of the unlocking script.
    pub unlocking_script_length: u32,
    /// Optional sequence number override.
    pub sequence_number: Option<u32>,
}

/// A single output for a create-action request.
#[derive(Debug, Clone)]
pub struct CreateActionOutput {
    /// The locking script bytes.
    pub locking_script: Vec<u8>,
    /// The satoshi value for this output.
    pub satoshis: u64,
    /// Human-readable description of this output.
    pub output_description: String,
    /// The basket to assign this output to.
    pub basket: String,
    /// Application-specific custom instructions.
    pub custom_instructions: String,
    /// Tags to associate with this output.
    pub tags: Vec<String>,
}

/// Result of a create-action operation.
#[derive(Debug, Clone)]
pub struct CreateActionResult {
    /// The 32-byte transaction ID.
    pub txid: [u8; 32],
    /// The raw serialized transaction bytes.
    pub tx: Vec<u8>,
}

/// Arguments for signing a previously created action.
#[derive(Debug, Clone)]
pub struct SignActionArgs {
    /// Opaque reference to the action to sign.
    pub reference: Vec<u8>,
    /// Map from input index to the spend data for that input.
    pub spends: std::collections::HashMap<u32, SignActionSpend>,
}

/// Spend data for a single input in a sign-action request.
#[derive(Debug, Clone)]
pub struct SignActionSpend {
    /// The unlocking script bytes for this input.
    pub unlocking_script: Vec<u8>,
    /// Optional sequence number override.
    pub sequence_number: Option<u32>,
}

/// Result of a sign-action operation.
#[derive(Debug, Clone)]
pub struct SignActionResult {
    /// The 32-byte transaction ID of the signed transaction.
    pub txid: [u8; 32],
    /// The raw serialized signed transaction bytes.
    pub tx: Vec<u8>,
}

/// Arguments for aborting a previously created action.
#[derive(Debug, Clone)]
pub struct AbortActionArgs {
    /// Opaque reference to the action to abort.
    pub reference: Vec<u8>,
}

/// Result of an abort-action operation.
#[derive(Debug, Clone)]
pub struct AbortActionResult {
    /// Whether the action was successfully aborted.
    pub aborted: bool,
}

/// Arguments for listing actions (transactions).
#[derive(Debug, Clone)]
pub struct ListActionsArgs {
    /// Filter actions by these labels.
    pub labels: Vec<String>,
    /// Maximum number of actions to return.
    pub limit: Option<u32>,
    /// Number of actions to skip before returning results.
    pub offset: Option<u32>,
}

/// Result of a list-actions query.
#[derive(Debug, Clone)]
pub struct ListActionsResult {
    /// Total number of actions matching the filter.
    pub total_actions: u32,
    /// The action records in this page.
    pub actions: Vec<ActionRecord>,
}

/// A single action (transaction) record.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// The 32-byte transaction ID.
    pub txid: [u8; 32],
    /// Net satoshi value of the action (negative for outgoing).
    pub satoshis: i64,
    /// Current status of the action (e.g. "completed", "pending").
    pub status: String,
    /// Whether this is an outgoing (spending) action.
    pub is_outgoing: bool,
    /// Human-readable description of the action.
    pub description: String,
}

/// Arguments for internalizing an external action.
#[derive(Debug, Clone)]
pub struct InternalizeActionArgs {
    /// The raw serialized transaction bytes.
    pub tx: Vec<u8>,
    /// Human-readable description of the action.
    pub description: String,
    /// Labels to associate with this action.
    pub labels: Vec<String>,
    /// Outputs to internalize from the transaction.
    pub outputs: Vec<InternalizeOutput>,
}

/// Specification of a single output to internalize.
#[derive(Debug, Clone)]
pub struct InternalizeOutput {
    /// The zero-based index of the output in the transaction.
    pub output_index: u32,
    /// The protocol that owns this output.
    pub protocol: String,
}

/// Result of an internalize-action operation.
#[derive(Debug, Clone)]
pub struct InternalizeActionResult {
    /// Whether the action was accepted for internalization.
    pub accepted: bool,
}

/// Arguments for listing wallet outputs.
#[derive(Debug, Clone)]
pub struct ListOutputsArgs {
    /// The basket to list outputs from.
    pub basket: String,
    /// Filter outputs by these tags.
    pub tags: Vec<String>,
    /// Maximum number of outputs to return.
    pub limit: Option<u32>,
    /// Number of outputs to skip before returning results.
    pub offset: Option<u32>,
}

/// Result of a list-outputs query.
#[derive(Debug, Clone)]
pub struct ListOutputsResult {
    /// Total number of outputs matching the filter.
    pub total_outputs: u32,
    /// The output records in this page.
    pub outputs: Vec<OutputRecord>,
}

/// A single wallet output record.
#[derive(Debug, Clone)]
pub struct OutputRecord {
    /// The satoshi value of this output.
    pub satoshis: u64,
    /// The locking script bytes.
    pub locking_script: Vec<u8>,
    /// Whether this output is currently spendable.
    pub spendable: bool,
    /// The outpoint identifier (txid:vout format).
    pub outpoint: String,
}

/// Arguments for relinquishing a wallet output.
#[derive(Debug, Clone)]
pub struct RelinquishOutputArgs {
    /// The basket containing the output.
    pub basket: String,
    /// The outpoint identifier of the output to relinquish.
    pub output: String,
}

/// Result of a relinquish-output operation.
#[derive(Debug, Clone)]
pub struct RelinquishOutputResult {
    /// Whether the output was successfully relinquished.
    pub relinquished: bool,
}

// === Key Linkage Types ===

/// Arguments for revealing counterparty key linkage to a verifier.
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageArgs {
    /// The counterparty whose key linkage to reveal.
    pub counterparty: PublicKey,
    /// The verifier who will receive the linkage proof.
    pub verifier: PublicKey,
}

/// Result of a counterparty key linkage reveal.
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageResult {
    /// The prover's public key.
    pub prover: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
    /// The verifier's public key.
    pub verifier: PublicKey,
    /// The encrypted key linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Proof that the encrypted linkage is correct.
    pub encrypted_linkage_proof: Vec<u8>,
}

/// Arguments for revealing specific key linkage for a protocol/keyID pair.
#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageArgs {
    /// The counterparty whose specific key linkage to reveal.
    pub counterparty: Counterparty,
    /// The verifier who will receive the linkage proof.
    pub verifier: PublicKey,
    /// The protocol under which the key was derived.
    pub protocol_id: Protocol,
    /// The key identifier within the protocol.
    pub key_id: String,
}

/// Result of a specific key linkage reveal.
#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageResult {
    /// The encrypted key linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Proof that the encrypted linkage is correct.
    pub encrypted_linkage_proof: Vec<u8>,
    /// The prover's public key.
    pub prover: PublicKey,
    /// The verifier's public key.
    pub verifier: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
    /// The protocol under which the key was derived.
    pub protocol_id: Protocol,
    /// The key identifier within the protocol.
    pub key_id: String,
}

// === Certificate Types ===

/// A 32-byte certificate type identifier.
pub type CertificateType = [u8; 32];
/// A 32-byte certificate serial number.
pub type SerialNumber = [u8; 32];

/// A verifiable certificate issued by a certifier to a subject.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The 32-byte type identifier for this certificate.
    pub cert_type: CertificateType,
    /// The unique 32-byte serial number.
    pub serial_number: SerialNumber,
    /// The subject (holder) of the certificate.
    pub subject: PublicKey,
    /// The certifier (issuer) of the certificate.
    pub certifier: PublicKey,
    /// Key-value map of certificate fields.
    pub fields: std::collections::HashMap<String, String>,
    /// The certifier's signature over the certificate.
    pub signature: Option<Signature>,
}

/// A certificate together with its decryption keyring.
#[derive(Debug, Clone)]
pub struct CertificateResult {
    /// The certificate data.
    pub certificate: Certificate,
    /// Map of field names to their decryption keys.
    pub keyring: std::collections::HashMap<String, String>,
}

/// Arguments for acquiring a certificate from a certifier.
#[derive(Debug, Clone)]
pub struct AcquireCertificateArgs {
    /// The 32-byte certificate type to acquire.
    pub cert_type: CertificateType,
    /// The certifier to request the certificate from.
    pub certifier: PublicKey,
    /// The acquisition protocol to use (e.g. "direct", "issuance").
    pub acquisition_protocol: String,
    /// Key-value map of requested certificate fields.
    pub fields: std::collections::HashMap<String, String>,
}

/// Arguments for listing certificates.
#[derive(Debug, Clone)]
pub struct ListCertificatesArgs {
    /// Filter by these certifier public keys.
    pub certifiers: Vec<PublicKey>,
    /// Filter by these certificate type identifiers.
    pub types: Vec<CertificateType>,
    /// Maximum number of certificates to return.
    pub limit: Option<u32>,
    /// Number of certificates to skip before returning results.
    pub offset: Option<u32>,
}

/// Result of a list-certificates query.
#[derive(Debug, Clone)]
pub struct ListCertificatesResult {
    /// Total number of certificates matching the filter.
    pub total_certificates: u32,
    /// The certificate records in this page.
    pub certificates: Vec<CertificateResult>,
}

/// Arguments for proving certificate fields to a verifier.
#[derive(Debug, Clone)]
pub struct ProveCertificateArgs {
    /// The certificate to prove.
    pub certificate: Certificate,
    /// The field names to reveal to the verifier.
    pub fields_to_reveal: Vec<String>,
    /// The verifier who will receive the proof.
    pub verifier: PublicKey,
}

/// Result of a prove-certificate operation.
#[derive(Debug, Clone)]
pub struct ProveCertificateResult {
    /// Map of field names to re-encrypted keys for the verifier.
    pub keyring_for_verifier: std::collections::HashMap<String, String>,
}

/// Arguments for relinquishing (deleting) a certificate.
#[derive(Debug, Clone)]
pub struct RelinquishCertificateArgs {
    /// The 32-byte certificate type identifier.
    pub cert_type: CertificateType,
    /// The 32-byte serial number of the certificate.
    pub serial_number: SerialNumber,
    /// The certifier who issued the certificate.
    pub certifier: PublicKey,
}

/// Result of a relinquish-certificate operation.
#[derive(Debug, Clone)]
pub struct RelinquishCertificateResult {
    /// Whether the certificate was successfully relinquished.
    pub relinquished: bool,
}

// === Discovery Types ===

/// Arguments for discovering certificates by identity key.
#[derive(Debug, Clone)]
pub struct DiscoverByIdentityKeyArgs {
    /// The identity key to search for.
    pub identity_key: PublicKey,
    /// Maximum number of certificates to return.
    pub limit: Option<u32>,
    /// Number of certificates to skip before returning results.
    pub offset: Option<u32>,
}

/// Arguments for discovering certificates by attributes.
#[derive(Debug, Clone)]
pub struct DiscoverByAttributesArgs {
    /// Key-value map of attributes to search for.
    pub attributes: std::collections::HashMap<String, String>,
    /// Maximum number of certificates to return.
    pub limit: Option<u32>,
    /// Number of certificates to skip before returning results.
    pub offset: Option<u32>,
}

/// Result of a certificate discovery query.
#[derive(Debug, Clone)]
pub struct DiscoverCertificatesResult {
    /// Total number of certificates matching the query.
    pub total_certificates: u32,
    /// The matching certificate records.
    pub certificates: Vec<CertificateResult>,
}

// === Auth / Info Types ===

/// Result of an authentication status check.
#[derive(Debug, Clone)]
pub struct AuthenticatedResult {
    /// Whether the wallet is currently authenticated.
    pub authenticated: bool,
}

/// Result of a get-height query.
#[derive(Debug, Clone)]
pub struct GetHeightResult {
    /// The current blockchain height.
    pub height: u32,
}

/// Arguments for retrieving a block header by height.
#[derive(Debug, Clone)]
pub struct GetHeaderArgs {
    /// The block height to retrieve the header for.
    pub height: u32,
}

/// Result of a get-header query.
#[derive(Debug, Clone)]
pub struct GetHeaderResult {
    /// The raw 80-byte block header.
    pub header: Vec<u8>,
}

/// Result of a get-network query.
#[derive(Debug, Clone)]
pub struct GetNetworkResult {
    /// The network name (e.g. "mainnet", "testnet").
    pub network: String,
}

/// Result of a get-version query.
#[derive(Debug, Clone)]
pub struct GetVersionResult {
    /// The wallet implementation version string.
    pub version: String,
}

/// Returns the special "anyone" private/public key pair (scalar = 1).
pub fn anyone_key() -> (bsv_primitives::ec::private_key::PrivateKey, PublicKey) {
    let priv_key = bsv_primitives::ec::private_key::PrivateKey::from_bytes(&[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
    .expect("anyone key should always be valid");
    let pub_key = priv_key.pub_key();
    (priv_key, pub_key)
}

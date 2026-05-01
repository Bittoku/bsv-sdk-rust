//! The 29-method Wallet interface trait.
//!
//! This mirrors the Go `wallet.Interface` — the full set of operations
//! a BSV wallet must support.

use crate::error::WalletError;
use crate::types::*;

/// The full wallet interface (29 methods).
///
/// Methods that are not implemented by ProtoWallet (transaction management,
/// certificates, blockchain queries) return `WalletError::General("not implemented")`.
pub trait WalletInterface {
    // === Key Operations ===

    /// Derive or retrieve a public key based on the given parameters.
    fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult, WalletError>;

    /// Encrypt plaintext using a derived symmetric key.
    fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult, WalletError>;
    /// Decrypt ciphertext using a derived symmetric key.
    fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult, WalletError>;

    /// Create an HMAC over data using a derived symmetric key.
    fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult, WalletError>;
    /// Verify an HMAC over data using a derived symmetric key.
    fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, WalletError>;

    /// Create a digital signature over data using a derived private key.
    fn create_signature(
        &self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, WalletError>;
    /// Verify a digital signature using a derived public key.
    fn verify_signature(
        &self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, WalletError>;

    // === Action / Transaction Operations ===

    /// Create a new transaction action with the specified inputs and outputs.
    fn create_action(&self, _args: CreateActionArgs) -> Result<CreateActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Provide unlocking scripts to sign a previously created action.
    fn sign_action(&self, _args: SignActionArgs) -> Result<SignActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Abort a previously created action before it is broadcast.
    fn abort_action(&self, _args: AbortActionArgs) -> Result<AbortActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// List transaction actions matching the given label filters.
    fn list_actions(&self, _args: ListActionsArgs) -> Result<ListActionsResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Internalize an external transaction into the wallet.
    fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
    ) -> Result<InternalizeActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// List wallet outputs matching the given basket and tag filters.
    fn list_outputs(&self, _args: ListOutputsArgs) -> Result<ListOutputsResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Relinquish (release) a wallet output so it is no longer tracked.
    fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
    ) -> Result<RelinquishOutputResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Key Linkage ===

    /// Reveal the key linkage between self and a counterparty to a verifier.
    fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Reveal the specific key linkage for a protocol/keyID pair to a verifier.
    fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Certificate Operations ===

    /// Acquire a certificate from a certifier.
    fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
    ) -> Result<CertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// List certificates matching the given certifier and type filters.
    fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
    ) -> Result<ListCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Prove selected fields of a certificate to a verifier.
    fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
    ) -> Result<ProveCertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Relinquish (delete) a certificate from the wallet.
    fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Discovery ===

    /// Discover certificates associated with a given identity key.
    fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Discover certificates matching a set of attribute key-value pairs.
    fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Authentication / Info ===

    /// Check whether the wallet is currently authenticated.
    fn is_authenticated(&self) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Block until the wallet becomes authenticated.
    fn wait_for_authentication(&self) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Get the current blockchain height known to the wallet.
    fn get_height(&self) -> Result<GetHeightResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Get the block header at the specified height.
    fn get_header_for_height(&self, _args: GetHeaderArgs) -> Result<GetHeaderResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Get the network the wallet is connected to (e.g. "mainnet").
    fn get_network(&self) -> Result<GetNetworkResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    /// Get the wallet implementation version string.
    fn get_version(&self) -> Result<GetVersionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
}

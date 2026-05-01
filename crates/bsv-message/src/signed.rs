//! BRC-77 message signing and verification.
//!
//! <https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0077.md>

use base64::Engine;
use rand::RngCore;

use bsv_primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_primitives::hash::sha256;

use crate::MessageError;

/// BRC-77 signed message version bytes.
const VERSION_BYTES: [u8; 4] = [0x42, 0x42, 0x33, 0x01];

/// Sign a message. If `verifier` is `None`, anyone can verify the signature.
pub fn sign(
    message: &[u8],
    signer: &PrivateKey,
    verifier: Option<&PublicKey>,
) -> Result<Vec<u8>, MessageError> {
    let recipient_anyone = verifier.is_none();

    // For "anyone" mode, use private key with scalar = 1
    let anyone_key;
    let anyone_pub;
    let verifier_pub = if recipient_anyone {
        let mut one = [0u8; 32];
        one[31] = 1;
        anyone_key = PrivateKey::from_bytes(&one).unwrap();
        anyone_pub = anyone_key.pub_key();
        &anyone_pub
    } else {
        verifier.unwrap()
    };

    let mut key_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key_id);

    let key_id_base64 = base64::engine::general_purpose::STANDARD.encode(key_id);
    let invoice_number = format!("2-message signing-{}", key_id_base64);

    let signing_priv = signer.derive_child(verifier_pub, &invoice_number)?;
    let hashed = sha256(message);
    let signature = signing_priv.sign(&hashed)?;

    let sender_pub = signer.pub_key().to_compressed();

    let mut sig_bytes = Vec::new();
    sig_bytes.extend_from_slice(&VERSION_BYTES);
    sig_bytes.extend_from_slice(&sender_pub);
    if recipient_anyone {
        sig_bytes.push(0);
    } else {
        sig_bytes.extend_from_slice(&verifier_pub.to_compressed());
    }
    sig_bytes.extend_from_slice(&key_id);
    sig_bytes.extend_from_slice(&signature.to_der());
    Ok(sig_bytes)
}

/// Verify a signed message. If `recipient` is `None`, verifies "anyone" signatures.
/// For recipient-specific signatures, provide the recipient's private key.
pub fn verify(
    message: &[u8],
    sig: &[u8],
    recipient: Option<&PrivateKey>,
) -> Result<bool, MessageError> {
    let mut counter = 0;

    // Version (4 bytes)
    if sig.len() < 4 {
        return Err(MessageError::General("signature too short".to_string()));
    }
    let msg_version = &sig[counter..counter + 4];
    counter += 4;
    if msg_version != VERSION_BYTES {
        return Err(MessageError::VersionMismatch {
            expected: hex::encode(VERSION_BYTES),
            received: hex::encode(msg_version),
        });
    }

    // Sender public key (33 bytes)
    if sig.len() < counter + 33 {
        return Err(MessageError::General(
            "signature too short for sender pubkey".to_string(),
        ));
    }
    let signer = PublicKey::from_bytes(&sig[counter..counter + 33])?;
    counter += 33;

    // Verifier: first byte determines mode
    if sig.len() < counter + 1 {
        return Err(MessageError::General(
            "signature too short for verifier".to_string(),
        ));
    }

    let anyone_key;
    let actual_recipient: &PrivateKey;

    let verifier_first = sig[counter];
    if verifier_first == 0 {
        // Anyone mode
        let mut one = [0u8; 32];
        one[31] = 1;
        anyone_key = PrivateKey::from_bytes(&one).unwrap();
        actual_recipient = if let Some(r) = recipient {
            // If recipient is provided but sig is "anyone", just use the anyone key
            let _ = r;
            // Actually Go code replaces recipient with key=1 in this branch
            &anyone_key
        } else {
            &anyone_key
        };
        counter += 1;
    } else {
        // Specific recipient mode
        counter += 1;
        if sig.len() < counter + 32 {
            return Err(MessageError::General(
                "signature too short for verifier pubkey".to_string(),
            ));
        }
        let verifier_rest = &sig[counter..counter + 32];
        counter += 32;
        let mut verifier_der = Vec::with_capacity(33);
        verifier_der.push(verifier_first);
        verifier_der.extend_from_slice(verifier_rest);

        let recipient = match recipient {
            Some(r) => r,
            None => {
                return Err(MessageError::VerifierRequired(hex::encode(&verifier_der)));
            }
        };

        let recipient_der = recipient.pub_key().to_compressed();
        if verifier_der != recipient_der.as_slice() {
            return Err(MessageError::WrongVerifier {
                expected: hex::encode(&verifier_der),
                actual: hex::encode(recipient_der),
            });
        }
        actual_recipient = recipient;
    }

    // Key ID (32 bytes)
    if sig.len() < counter + 32 {
        return Err(MessageError::General(
            "signature too short for key ID".to_string(),
        ));
    }
    let key_id = &sig[counter..counter + 32];
    counter += 32;

    // Signature DER (rest)
    let signature_der = &sig[counter..];
    let signature = Signature::from_der(signature_der)?;

    let key_id_base64 = base64::engine::general_purpose::STANDARD.encode(key_id);
    let invoice_number = format!("2-message signing-{}", key_id_base64);

    let signing_key = signer.derive_child(actual_recipient, &invoice_number)?;

    let hashed = sha256(message);
    Ok(signature.verify(&hashed, &signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_key_from_short(b: &[u8]) -> PrivateKey {
        let mut padded = [0u8; 32];
        padded[32 - b.len()..].copy_from_slice(b);
        PrivateKey::from_bytes(&padded).unwrap()
    }

    #[test]
    fn test_sign_for_recipient() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let message = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message, &sender, Some(&recipient_pub)).unwrap();
        let verified = verify(&message, &signature, Some(&recipient)).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_sign_for_anyone() {
        let sender = priv_key_from_short(&[15]);

        let message = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message, &sender, None).unwrap();
        let verified = verify(&message, &signature, None).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_verify_wrong_version() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let message = vec![1, 2, 4, 8, 16, 32];
        let mut signature = sign(&message, &sender, Some(&recipient_pub)).unwrap();
        signature[0] = 1;

        let err = verify(&message, &signature, Some(&recipient)).unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("message version mismatch"),
            "got: {}",
            err_str
        );
        assert!(err_str.contains("42423301"), "got: {}", err_str);
        assert!(err_str.contains("01423301"), "got: {}", err_str);
    }

    #[test]
    fn test_verify_no_verifier_when_required() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let message = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message, &sender, Some(&recipient_pub)).unwrap();

        let result = verify(&message, &signature, None);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains(
                "this signature can only be verified with knowledge of a specific private key"
            ),
            "got: {}",
            err_str
        );
        let expected_hex = hex::encode(recipient_pub.to_compressed());
        assert!(err_str.contains(&expected_hex), "got: {}", err_str);
    }

    #[test]
    fn test_verify_wrong_verifier() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();
        let wrong_recipient = priv_key_from_short(&[22]);

        let message = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message, &sender, Some(&recipient_pub)).unwrap();

        let result = verify(&message, &signature, Some(&wrong_recipient));
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        let expected_pub_hex = hex::encode(recipient_pub.to_compressed());
        let actual_pub_hex = hex::encode(wrong_recipient.pub_key().to_compressed());
        assert!(err_str.contains(&actual_pub_hex), "got: {}", err_str);
        assert!(err_str.contains(&expected_pub_hex), "got: {}", err_str);
    }

    #[test]
    fn test_tampered_message_anyone() {
        let sender = priv_key_from_short(&[15]);

        let message_a = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message_a, &sender, None).unwrap();

        let mut message_b = message_a.clone();
        let last = message_b.len() - 1;
        message_b[last] = 64;

        let verified = verify(&message_b, &signature, None).unwrap();
        assert!(!verified, "Verification should fail for a tampered message");
    }

    #[test]
    fn test_tampered_message_specific_recipient() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let message_a = vec![1, 2, 4, 8, 16, 32];
        let signature = sign(&message_a, &sender, Some(&recipient_pub)).unwrap();

        let mut message_b = message_a.clone();
        let last = message_b.len() - 1;
        message_b[last] = 64;

        let verified = verify(&message_b, &signature, Some(&recipient)).unwrap();
        assert!(!verified, "Verification should fail for a tampered message");
    }
}

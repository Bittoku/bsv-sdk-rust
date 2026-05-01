//! Tests for certificates: Certificate, MasterCertificate, VerifiableCertificate.

use bsv_auth::certificates::{
    create_certificate_fields, create_keyring_for_verifier, decrypt_field, decrypt_fields,
    issue_certificate_for_subject, Certificate, MasterCertificate, VerifiableCertificate,
};
use bsv_auth::utils::random_base64;
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_wallet::types::{Counterparty, CounterpartyType};
use bsv_wallet::{ProtoWallet, ProtoWalletArgs};
use std::collections::HashMap;

fn make_wallet(pk: &PrivateKey) -> ProtoWallet {
    ProtoWallet::new(ProtoWalletArgs::PrivateKey(pk.clone())).unwrap()
}

#[test]
fn test_certificate_sign_and_verify() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let certifier_wallet = make_wallet(&certifier_pk);

    let mut fields = HashMap::new();
    fields.insert("name".to_string(), "Alice".to_string());
    fields.insert("email".to_string(), "alice@example.com".to_string());

    let mut cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        subject_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        fields,
    );

    // Sign
    cert.sign(&certifier_wallet).unwrap();
    assert!(!cert.signature.is_empty());

    // Verify
    cert.verify().unwrap();
}

#[test]
fn test_certificate_tampered_fails_verification() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let certifier_wallet = make_wallet(&certifier_pk);

    let mut fields = HashMap::new();
    fields.insert("name".to_string(), "Alice".to_string());

    let mut cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        subject_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        fields,
    );

    cert.sign(&certifier_wallet).unwrap();

    // Tamper
    cert.fields
        .insert("name".to_string(), "attacker".to_string());

    assert!(cert.verify().is_err());
}

#[test]
fn test_certificate_unsigned_fails_verification() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();

    let cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        subject_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        HashMap::new(),
    );

    assert!(cert.verify().is_err());
}

#[test]
fn test_certificate_double_sign_fails() {
    let certifier_pk = PrivateKey::new();
    let certifier_wallet = make_wallet(&certifier_pk);

    let mut cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        certifier_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        HashMap::new(),
    );

    cert.sign(&certifier_wallet).unwrap();
    assert!(cert.sign(&certifier_wallet).is_err());
}

#[test]
fn test_certificate_serialize_deserialize() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let certifier_wallet = make_wallet(&certifier_pk);

    let mut fields = HashMap::new();
    fields.insert("name".to_string(), "Alice".to_string());
    fields.insert("email".to_string(), "alice@example.com".to_string());

    let mut cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        subject_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        fields.clone(),
    );

    cert.sign(&certifier_wallet).unwrap();

    // Serialize with signature
    let binary = cert.to_binary(true).unwrap();
    let deserialized = Certificate::from_binary(&binary).unwrap();

    assert_eq!(cert.cert_type, deserialized.cert_type);
    assert_eq!(cert.serial_number, deserialized.serial_number);
    assert_eq!(cert.subject, deserialized.subject);
    assert_eq!(cert.certifier, deserialized.certifier);
    assert_eq!(cert.fields, deserialized.fields);
    assert_eq!(cert.signature, deserialized.signature);

    // Deserialized should also verify
    deserialized.verify().unwrap();
}

#[test]
fn test_certificate_serialize_without_signature() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();

    let mut fields = HashMap::new();
    fields.insert("name".to_string(), "Alice".to_string());

    let cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        subject_pk.pub_key(),
        certifier_pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        fields,
    );

    let binary = cert.to_binary(false).unwrap();
    let deserialized = Certificate::from_binary(&binary).unwrap();

    assert_eq!(cert.cert_type, deserialized.cert_type);
    assert!(deserialized.signature.is_empty());
}

#[test]
fn test_issue_certificate_and_decrypt_fields() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let subject_wallet = make_wallet(&subject_pk);
    let certifier_wallet = make_wallet(&certifier_pk);

    let subject_pub = subject_pk.pub_key();
    let certifier_pub = certifier_pk.pub_key();

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());

    let subject_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(subject_pub.clone()),
    };

    let master_cert = issue_certificate_for_subject(
        &certifier_wallet,
        &subject_counterparty,
        &plain_fields,
        &random_base64(32),
        None,
        None,
    )
    .unwrap();

    // Verify the certificate is signed
    assert!(!master_cert.certificate.signature.is_empty());
    master_cert.certificate.verify().unwrap();

    // Decrypt fields using subject wallet
    let certifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(certifier_pub.clone()),
    };

    let decrypted = decrypt_fields(
        &subject_wallet,
        &master_cert.master_keyring,
        &master_cert.certificate.fields,
        &certifier_counterparty,
    )
    .unwrap();

    assert_eq!(decrypted.get("name").unwrap(), "Alice");
    assert_eq!(decrypted.get("email").unwrap(), "alice@example.com");
}

#[test]
fn test_create_keyring_for_verifier_and_decrypt() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let verifier_pk = PrivateKey::new();

    let subject_wallet = make_wallet(&subject_pk);
    let certifier_wallet = make_wallet(&certifier_pk);
    let verifier_wallet = make_wallet(&verifier_pk);

    let subject_pub = subject_pk.pub_key();
    let certifier_pub = certifier_pk.pub_key();
    let verifier_pub = verifier_pk.pub_key();

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    let subject_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(subject_pub.clone()),
    };

    let master_cert = issue_certificate_for_subject(
        &certifier_wallet,
        &subject_counterparty,
        &plain_fields,
        &random_base64(32),
        None,
        None,
    )
    .unwrap();

    // Create keyring for verifier revealing only "name"
    let certifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(certifier_pub.clone()),
    };
    let verifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(verifier_pub.clone()),
    };

    let keyring_for_verifier = create_keyring_for_verifier(
        &subject_wallet,
        &certifier_counterparty,
        &verifier_counterparty,
        &master_cert.certificate.fields,
        &["name".to_string()],
        &master_cert.master_keyring,
        &master_cert.certificate.serial_number,
    )
    .unwrap();

    assert_eq!(keyring_for_verifier.len(), 1);
    assert!(keyring_for_verifier.contains_key("name"));

    // Verifier can decrypt
    let mut verifiable =
        VerifiableCertificate::new(master_cert.certificate.clone(), keyring_for_verifier);

    let decrypted = verifiable.decrypt_fields(&verifier_wallet).unwrap();
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted.get("name").unwrap(), "Alice");
}

#[test]
fn test_verifiable_certificate_wrong_wallet_fails() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let verifier_pk = PrivateKey::new();
    let wrong_pk = PrivateKey::new();

    let subject_wallet = make_wallet(&subject_pk);
    let certifier_wallet = make_wallet(&certifier_pk);
    let wrong_wallet = make_wallet(&wrong_pk);

    let subject_pub = subject_pk.pub_key();
    let certifier_pub = certifier_pk.pub_key();
    let verifier_pub = verifier_pk.pub_key();

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());

    let subject_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(subject_pub.clone()),
    };

    let master_cert = issue_certificate_for_subject(
        &certifier_wallet,
        &subject_counterparty,
        &plain_fields,
        &random_base64(32),
        None,
        None,
    )
    .unwrap();

    let certifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(certifier_pub.clone()),
    };
    let verifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(verifier_pub.clone()),
    };

    let keyring = create_keyring_for_verifier(
        &subject_wallet,
        &certifier_counterparty,
        &verifier_counterparty,
        &master_cert.certificate.fields,
        &["name".to_string()],
        &master_cert.master_keyring,
        &master_cert.certificate.serial_number,
    )
    .unwrap();

    // Wrong wallet should fail
    let mut verifiable = VerifiableCertificate::new(master_cert.certificate.clone(), keyring);
    assert!(verifiable.decrypt_fields(&wrong_wallet).is_err());
}

#[test]
fn test_self_signed_certificate() {
    let subject_pk = PrivateKey::new();
    let subject_wallet = make_wallet(&subject_pk);

    let mut plain_fields = HashMap::new();
    plain_fields.insert("owner".to_string(), "Bob".to_string());

    let self_counterparty = Counterparty {
        r#type: CounterpartyType::Self_,
        counterparty: None,
    };

    let master_cert = issue_certificate_for_subject(
        &subject_wallet,
        &self_counterparty,
        &plain_fields,
        &random_base64(32),
        None,
        None,
    )
    .unwrap();

    // Verify
    master_cert.certificate.verify().unwrap();

    // Decrypt using same wallet
    let decrypted = decrypt_fields(
        &subject_wallet,
        &master_cert.master_keyring,
        &master_cert.certificate.fields,
        &self_counterparty,
    )
    .unwrap();

    assert_eq!(decrypted.get("owner").unwrap(), "Bob");
}

#[test]
fn test_master_certificate_missing_keyring() {
    let pk = PrivateKey::new();
    let cert = Certificate::new(
        random_base64(32),
        random_base64(32),
        pk.pub_key(),
        pk.pub_key(),
        format!("{}.0", "00".repeat(32)),
        {
            let mut f = HashMap::new();
            f.insert("field".to_string(), "value".to_string());
            f
        },
    );

    // Empty keyring should fail
    let result = MasterCertificate::new(cert, HashMap::new());
    assert!(result.is_err());
}

#[test]
fn test_keyring_for_nonexistent_field_fails() {
    let subject_pk = PrivateKey::new();
    let certifier_pk = PrivateKey::new();
    let verifier_pk = PrivateKey::new();

    let subject_wallet = make_wallet(&subject_pk);
    let certifier_wallet = make_wallet(&certifier_pk);

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());

    let subject_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(subject_pk.pub_key()),
    };

    let master_cert = issue_certificate_for_subject(
        &certifier_wallet,
        &subject_counterparty,
        &plain_fields,
        &random_base64(32),
        None,
        None,
    )
    .unwrap();

    let certifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(certifier_pk.pub_key()),
    };
    let verifier_counterparty = Counterparty {
        r#type: CounterpartyType::Other,
        counterparty: Some(verifier_pk.pub_key()),
    };

    let result = create_keyring_for_verifier(
        &subject_wallet,
        &certifier_counterparty,
        &verifier_counterparty,
        &master_cert.certificate.fields,
        &["nonexistent_field".to_string()],
        &master_cert.master_keyring,
        &master_cert.certificate.serial_number,
    );

    assert!(result.is_err());
}

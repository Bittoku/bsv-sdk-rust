//! Tests for utility functions.

use bsv_auth::types::RequestedCertificateSet;
use bsv_auth::utils::{certifier_in_slice, random_base64, validate_requested_certificate_set};
use bsv_primitives::ec::private_key::PrivateKey;
use std::collections::HashMap;

#[test]
fn test_random_base64() {
    let a = random_base64(32);
    let b = random_base64(32);
    assert!(!a.is_empty());
    assert!(!b.is_empty());
    assert_ne!(a, b);

    // Base64 of 32 bytes should be 44 chars
    assert_eq!(a.len(), 44);
}

#[test]
fn test_certifier_in_slice() {
    let pk1 = PrivateKey::new().pub_key();
    let pk2 = PrivateKey::new().pub_key();
    let pk3 = PrivateKey::new().pub_key();

    assert!(certifier_in_slice(&[pk1.clone(), pk2.clone()], &pk1));
    assert!(certifier_in_slice(&[pk1.clone(), pk2.clone()], &pk2));
    assert!(!certifier_in_slice(&[pk1.clone(), pk2.clone()], &pk3));
    assert!(!certifier_in_slice(&[], &pk1));
}

#[test]
fn test_validate_requested_certificate_set() {
    let pk = PrivateKey::new().pub_key();

    // Empty certifiers
    let req = RequestedCertificateSet {
        certifiers: vec![],
        certificate_types: {
            let mut m = HashMap::new();
            m.insert([1u8; 32], vec!["field1".to_string()]);
            m
        },
    };
    assert!(validate_requested_certificate_set(&req).is_err());

    // Empty types
    let req = RequestedCertificateSet {
        certifiers: vec![pk.clone()],
        certificate_types: HashMap::new(),
    };
    assert!(validate_requested_certificate_set(&req).is_err());

    // Empty type key
    let req = RequestedCertificateSet {
        certifiers: vec![pk.clone()],
        certificate_types: {
            let mut m = HashMap::new();
            m.insert([0u8; 32], vec!["field1".to_string()]);
            m
        },
    };
    assert!(validate_requested_certificate_set(&req).is_err());

    // Empty fields for a type
    let req = RequestedCertificateSet {
        certifiers: vec![pk.clone()],
        certificate_types: {
            let mut m = HashMap::new();
            m.insert([1u8; 32], vec![]);
            m
        },
    };
    assert!(validate_requested_certificate_set(&req).is_err());

    // Valid
    let req = RequestedCertificateSet {
        certifiers: vec![pk],
        certificate_types: {
            let mut m = HashMap::new();
            m.insert([1u8; 32], vec!["field1".to_string()]);
            m
        },
    };
    assert!(validate_requested_certificate_set(&req).is_ok());
}

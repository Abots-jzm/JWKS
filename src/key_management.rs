// This project was developed with assistance from GitHub Copilot
// Key management functionality for the JWKS server

use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use uuid::Uuid;

use crate::types::KeyPair;

impl KeyPair {
    /// Generate a new RSA key pair with expiry
    pub fn new(expiry_hours: i64) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);

        let kid = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(expiry_hours);

        Ok(KeyPair {
            kid,
            private_key,
            public_key,
            expires_at,
        })
    }

    /// Check if the key pair has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the key pair is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }
}

/// Serialize an RSA private key to PKCS#1 PEM (LF line endings) for DB storage.
pub fn private_key_to_pkcs1_pem(key: &RsaPrivateKey) -> Result<String, Box<dyn std::error::Error>> {
    let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    Ok(pem.to_string())
}

/// Deserialize an RSA private key from PKCS#1 PEM text read from the DB.
pub fn private_key_from_pkcs1_pem(pem: &str) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let key = RsaPrivateKey::from_pkcs1_pem(pem)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_key_pair_generation() {
        let key = KeyPair::new(24).expect("Failed to generate key pair");

        assert!(!key.kid.is_empty());

        assert!(key.is_valid());
        assert!(!key.is_expired());

        assert!(key.expires_at > Utc::now());
    }

    #[test]
    fn test_expired_key_generation() {
        let key = KeyPair::new(-1).expect("Failed to generate expired key pair");

        assert!(key.is_expired());
        assert!(!key.is_valid());

        assert!(key.expires_at < Utc::now());
    }

    #[test]
    fn test_key_expiry_validation() {
        let valid_key = KeyPair::new(1).expect("Failed to generate key");
        assert!(valid_key.is_valid());

        let expired_key = KeyPair::new(-24).expect("Failed to generate expired key");
        assert!(expired_key.is_expired());
    }

    #[test]
    fn test_unique_key_ids() {
        let key1 = KeyPair::new(24).expect("Failed to generate key 1");
        let key2 = KeyPair::new(24).expect("Failed to generate key 2");

        assert_ne!(key1.kid, key2.kid);
    }

    #[test]
    fn test_key_components() {
        let key = KeyPair::new(24).expect("Failed to generate key pair");

        assert_eq!(key.public_key.size(), 2048 / 8); // 2048 bits = 256 bytes

        assert!(!key.public_key.n().to_bytes_be().is_empty());
        assert!(!key.public_key.e().to_bytes_be().is_empty());
    }

    #[test]
    fn test_pkcs1_pem_roundtrip() {
        let key = KeyPair::new(1).expect("Failed to generate key pair");
        let pem = private_key_to_pkcs1_pem(&key.private_key).expect("to pem failed");
        let parsed = private_key_from_pkcs1_pem(&pem).expect("from pem failed");

        // Compare modulus to ensure same key material
        assert_eq!(
            rsa::RsaPublicKey::from(&parsed).n().to_bytes_be(),
            key.public_key.n().to_bytes_be()
        );
    }

    #[test]
    fn test_pkcs1_pem_invalid_input() {
        let bad =
            "-----BEGIN RSA PRIVATE KEY-----\nnot a real key\n-----END RSA PRIVATE KEY-----\n";
        let err = private_key_from_pkcs1_pem(bad).err();
        assert!(err.is_some());
    }
}

// This project was developed with assistance from GitHub Copilot
// Key management functionality for the JWKS server

use chrono::{Duration, Utc};
use rand::rngs::OsRng;
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
}

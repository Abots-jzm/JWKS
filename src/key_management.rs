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

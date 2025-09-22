// This project was developed with assistance from GitHub Copilot
// Data structures for the JWKS server

use chrono::{DateTime, Utc};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

/// RSA key pair with metadata
#[derive(Clone)]
pub struct KeyPair {
    pub kid: String,                // Key ID
    pub private_key: RsaPrivateKey, // RSA private key
    pub public_key: RsaPublicKey,   // RSA public key
    pub expires_at: DateTime<Utc>,  // Expiry timestamp
}

/// JSON Web Key structure for JWKS response
#[derive(Serialize)]
pub struct JsonWebKey {
    pub kty: String, // Key type (RSA)
    pub kid: String, // Key ID
    #[serde(rename = "use")]
    pub key_use: String, // Key usage (sig for signature)
    pub alg: String, // Algorithm (RS256)
    pub n: String,   // Modulus (base64url)
    pub e: String,   // Exponent (base64url)
}

/// JWKS response format
#[derive(Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JsonWebKey>,
}

/// JWT Claims structure
#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject
    pub iat: i64,    // Issued at
    pub exp: i64,    // Expires at
    pub iss: String, // Issuer
}

/// Auth endpoint response
#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

/// Query parameters for auth endpoint
#[derive(Deserialize)]
pub struct AuthQuery {
    pub expired: Option<String>,
}

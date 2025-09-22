// This project was developed with assistance from GitHub Copilot
// JWKS endpoint implementation

use axum::{extract::State, http::StatusCode, response::Json};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::traits::PublicKeyParts;
use std::sync::Arc;

use crate::types::{JsonWebKey, JwksResponse, KeyPair};

/// Application state containing key pairs
pub type AppState = Arc<Vec<KeyPair>>;

/// JWKS endpoint handler - serves public keys in JWKS format
/// Only returns keys that have not expired
pub async fn jwks_handler(State(keys): State<AppState>) -> Result<Json<JwksResponse>, StatusCode> {
    // Filter out expired keys
    let valid_keys: Vec<JsonWebKey> = keys
        .iter()
        .filter(|key| key.is_valid())
        .map(|key| {
            // Extract RSA public key components
            let n = key.public_key.n();
            let e = key.public_key.e();

            // Convert to base64url format (without padding)
            let n_bytes = n.to_bytes_be();
            let e_bytes = e.to_bytes_be();
            let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
            let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

            JsonWebKey {
                kty: "RSA".to_string(),
                kid: key.kid.clone(),
                key_use: "sig".to_string(),
                alg: "RS256".to_string(),
                n: n_b64,
                e: e_b64,
            }
        })
        .collect();

    let response = JwksResponse { keys: valid_keys };
    Ok(Json(response))
}

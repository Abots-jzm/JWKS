// This project was developed with assistance from GitHub Copilot
// JWKS endpoint implementation

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use std::sync::Arc;

use crate::types::{AuthQuery, AuthResponse, Claims, JsonWebKey, JwksResponse, KeyPair};

/// Application state containing key pairs
pub type AppState = Arc<Vec<KeyPair>>;

/// JWKS endpoint handler - serves public keys in JWKS format
/// Only returns keys that have not expired
pub async fn jwks_handler(State(keys): State<AppState>) -> Result<Json<JwksResponse>, StatusCode> {
    let valid_keys: Vec<JsonWebKey> = keys
        .iter()
        .filter(|key| key.is_valid())
        .map(|key| {
            let n = key.public_key.n();
            let e = key.public_key.e();

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

/// Auth endpoint handler - issues JWTs for authentication
/// Supports 'expired' query parameter to use expired keys for testing
pub async fn auth_handler(
    State(keys): State<AppState>,
    Query(params): Query<AuthQuery>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let key_to_use = if params.expired.is_some() {
        keys.iter().find(|k| k.is_expired())
    } else {
        keys.iter().find(|k| k.is_valid())
    };

    let key = match key_to_use {
        Some(k) => k,
        None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Create JWT claims with appropriate expiry based on key type
    let now = Utc::now().timestamp();
    let exp = if params.expired.is_some() {
        // If using expired parameter, make the JWT itself expired (1 hour ago)
        now - 3600
    } else {
        // Normal case: 1 hour in the future
        now + 3600
    };

    let claims = Claims {
        sub: "user123".to_string(), // Simple static user for educational purposes
        iat: now,
        exp,
        iss: "jwks-server".to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());

    // Convert private key to PEM format for jsonwebtoken
    let private_key_pem = key
        .private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token =
        encode(&header, &claims, &encoding_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = AuthResponse { token };
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{create_app, initialize_keys};
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn get_test_app() -> Router {
        let keys = initialize_keys().expect("Failed to initialize test keys");
        let app_state = Arc::new(keys);
        create_app(app_state)
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let app = get_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        // Check that response contains JWKS structure
        assert!(body_str.contains("\"keys\""));
        assert!(body_str.contains("\"kty\""));
        assert!(body_str.contains("\"RSA\""));
    }

    #[tokio::test]
    async fn test_auth_endpoint() {
        let app = get_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        assert!(body_str.contains("\"token\""));

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
            if let Some(token) = json["token"].as_str() {
                let parts: Vec<&str> = token.split('.').collect();
                assert_eq!(parts.len(), 3);
            }
        }
    }

    #[tokio::test]
    async fn test_auth_endpoint_with_expired() {
        let app = get_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth?expired=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();

        assert!(body_str.contains("\"token\""));
    }

    #[tokio::test]
    async fn test_alternative_jwks_endpoint() {
        let app = get_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/jwks").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

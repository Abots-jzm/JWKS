// This project was developed with assistance from GitHub Copilot
// JWKS endpoint implementation (DB-backed)

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::traits::PublicKeyParts;
use std::sync::Arc;

use crate::db;
use crate::key_management::private_key_from_pkcs1_pem;
use crate::types::{AuthQuery, AuthResponse, Claims, JsonWebKey, JwksResponse};

/// Application state (placeholder; DB is global file). Using unit state keeps Axum happy.
pub type AppState = Arc<()>;

/// JWKS endpoint handler - serves public keys in JWKS format
/// Only returns keys that have not expired
pub async fn jwks_handler(
    State(_state): State<AppState>,
) -> Result<Json<JwksResponse>, StatusCode> {
    // Perform DB work off the main async thread
    let rows = tokio::task::spawn_blocking(|| db::select_all_valid_keys())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut jwks = Vec::new();
    for (kid_i64, pem_bytes, _exp) in rows {
        let pem_str = match String::from_utf8(pem_bytes) {
            Ok(s) => s,
            Err(_) => continue, // skip malformed rows safely
        };
        // Parse private key to derive public parameters
        let private =
            private_key_from_pkcs1_pem(&pem_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let public = rsa::RsaPublicKey::from(&private);

        let n_b64 = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());

        jwks.push(JsonWebKey {
            kty: "RSA".to_string(),
            kid: kid_i64.to_string(),
            key_use: "sig".to_string(),
            alg: "RS256".to_string(),
            n: n_b64,
            e: e_b64,
        });
    }

    Ok(Json(JwksResponse { keys: jwks }))
}

/// Auth endpoint handler - issues JWTs for authentication
/// Supports 'expired' query parameter to use expired keys for testing
pub async fn auth_handler(
    State(_state): State<AppState>,
    Query(params): Query<AuthQuery>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Choose expired or valid key from DB
    let want_expired = params.expired.is_some();
    let row = tokio::task::spawn_blocking(move || db::select_one_key(want_expired))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let (kid_i64, pem_bytes, _exp) = row;
    let pem_str = String::from_utf8(pem_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build claims (token itself valid for 1 hour regardless of key expiry)
    let now = Utc::now().timestamp();
    let exp = now + 3600;
    let claims = Claims {
        sub: "userABC".to_string(),
        iat: now,
        exp,
        iss: "jwks-server".to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid_i64.to_string());

    // Use PKCS#1 PEM directly for jsonwebtoken
    let encoding_key = EncodingKey::from_rsa_pem(pem_str.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token =
        encode(&header, &claims, &encoding_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AuthResponse { token }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::create_app;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn get_test_app() -> Router {
        // Ensure DB exists and seeded
        crate::db::init_db_and_seed().expect("db init failed");
        let app_state = Arc::new(());
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

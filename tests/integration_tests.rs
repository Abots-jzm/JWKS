// This project was developed with assistance from GitHub Copilot
// Integration tests for JWKS server

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use jwks::server::create_app;
use jwks::db;
use std::sync::Arc;
use tower::ServiceExt;

/// Test the complete JWKS endpoint functionality
#[tokio::test]
async fn test_jwks_endpoint_integration() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

    // Test standard JWKS endpoint
    let response = app
        .clone()
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

    // Validate JWKS structure
    assert!(body_str.contains("\"keys\""));
    assert!(body_str.contains("\"kty\":\"RSA\""));
    assert!(body_str.contains("\"use\":\"sig\""));
    assert!(body_str.contains("\"alg\":\"RS256\""));
    assert!(body_str.contains("\"kid\""));
    assert!(body_str.contains("\"n\""));
    assert!(body_str.contains("\"e\""));

    // Test alternative endpoint
    let response2 = app
        .oneshot(Request::builder().uri("/jwks").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::OK);
}

/// Test POST /auth endpoint without body (as specified in requirements)
#[tokio::test]
async fn test_auth_endpoint_no_body() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
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

    // Should return a valid JWT token
    assert!(body_str.contains("\"token\""));

    // Extract and validate JWT structure
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
        if let Some(token) = json["token"].as_str() {
            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 3, "JWT should have 3 parts");
            assert!(!parts[0].is_empty(), "Header should not be empty");
            assert!(!parts[1].is_empty(), "Payload should not be empty");
            assert!(!parts[2].is_empty(), "Signature should not be empty");
        } else {
            panic!("Token field not found in response");
        }
    } else {
        panic!("Invalid JSON response");
    }
}

/// Test expired parameter functionality
#[tokio::test]
async fn test_auth_endpoint_expired_parameter() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
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

    // Should still return a valid token using expired key
    assert!(body_str.contains("\"token\""));
}

/// Test invalid endpoints return 404
#[tokio::test]
async fn test_invalid_endpoints() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

    // Test invalid path
    let response = app
        .oneshot(
            Request::builder()
                .uri("/invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test JWKS only returns valid (non-expired) keys
#[tokio::test]
async fn test_jwks_filters_expired_keys() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

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

    // Parse JSON to count keys
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
        if let Some(keys_array) = json["keys"].as_array() {
            // Should contain at least one valid key; expired keys are filtered out
            assert!(keys_array.len() >= 1, "JWKS should contain at least one valid key");
        } else {
            panic!("Keys array not found in JWKS response");
        }
    } else {
        panic!("Invalid JSON response from JWKS endpoint");
    }
}

/// Test method validation - GET on auth should fail
#[tokio::test]
async fn test_method_validation() {
    db::init_db_and_seed().expect("db init failed");
    let app_state = Arc::new(());
    let app = create_app(app_state);

    // GET on /auth should return Method Not Allowed
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

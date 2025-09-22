// This project was developed with assistance from GitHub Copilot
// Server setup and configuration

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::endpoints::{AppState, auth_handler, jwks_handler};
use crate::types::KeyPair;

/// Create the application router with all endpoints
pub fn create_app(app_state: AppState) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/jwks", get(jwks_handler)) // Alternative endpoint
        .route("/auth", post(auth_handler))
        .with_state(app_state)
}

/// Initialize key pairs for the server
/// Creates one valid key and one expired key for testing
pub fn initialize_keys() -> Result<Vec<KeyPair>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();

    // Create a valid key (expires in 24 hours)
    let valid_key = KeyPair::new(24)?;
    keys.push(valid_key);

    // Create an expired key (expired 1 hour ago)
    let expired_key = KeyPair::new(-1)?;
    keys.push(expired_key);

    Ok(keys)
}

pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    let keys = initialize_keys()?;
    let app_state = Arc::new(keys);

    let app = create_app(app_state);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("JWKS server listening on http://0.0.0.0:8080");
    println!("Endpoints:");
    println!("  GET  /.well-known/jwks.json - JWKS endpoint");
    println!("  GET  /jwks                   - Alternative JWKS endpoint");
    println!("  POST /auth                   - Authentication endpoint");
    println!("  POST /auth?expired           - Auth with expired key");

    axum::serve(listener, app).await?;

    Ok(())
}

// This project was developed with assistance from GitHub Copilot
// Server setup and configuration

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::db;
use crate::endpoints::{AppState, auth_handler, jwks_handler};

/// Create the application router with all endpoints
pub fn create_app(app_state: AppState) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .route("/jwks", get(jwks_handler)) // Alternative endpoint
        .route("/auth", post(auth_handler))
        .with_state(app_state)
}

pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the SQLite database and seed keys so external clients can find them
    db::init_db_and_seed()?;
    let app_state = Arc::new(());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_app() {
        let app_state = Arc::new(());

    // This should not panic
    let _app = create_app(app_state);
    }
}

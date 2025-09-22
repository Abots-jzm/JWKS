// This project was developed with assistance from GitHub Copilot
// Educational JWKS server implementation
//
// This is a RESTful JWKS (JSON Web Key Set) server that provides public keys
// for verifying JSON Web Tokens (JWTs). It includes key expiry functionality
// and an authentication endpoint for educational purposes.

use jwks::server;

#[tokio::main]
async fn main() {
    if let Err(e) = server::start_server().await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}

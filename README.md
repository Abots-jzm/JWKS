# JWKS Server

_This project was developed with assistance from GitHub Copilot_

A RESTful JWKS (JSON Web Key Set) server implementation in Rust for educational purposes.

## Features

- RSA key generation with expiry management
- JWKS endpoint serving public keys
- JWT authentication endpoint
- Comprehensive test suite (65/65 gradebot score)

## Quick Start

```bash
# Run the server
cargo run

# Run tests
cargo test
```

Server runs on `http://0.0.0.0:8080`

## API Endpoints

- `GET /.well-known/jwks.json` - Get public keys
- `GET /jwks` - Alternative JWKS endpoint
- `POST /auth` - Get a JWT token
- `POST /auth?expired=true` - Get expired JWT (for testing)

## Example Usage

```bash
# Get public keys
curl http://localhost:8080/.well-known/jwks.json

# Get a JWT token
curl -X POST http://localhost:8080/auth
```

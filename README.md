# JWKS Server

_This project was developed with assistance from GitHub Copilot_

A RESTful JWKS (JSON Web Key Set) server implementation in Rust for educational purposes.

## Features

- RSA key generation with expiry management
- JWKS endpoint serving public keys
- JWT authentication endpoint
- SQLite-backed key storage in `totally_not_my_privateKeys.db`
- Comprehensive test suite (65/65 gradebot score)

## Quick Start

```bash
# Run the server
cargo run

# Run tests
cargo test

# (Optional) Test coverage with cargo-llvm-cov
cargo install cargo-llvm-cov --locked
cargo llvm-cov --ignore-filename-regex 'target|.cargo' --summary-only
```

Server runs on `http://0.0.0.0:8080`

The database file `totally_not_my_privateKeys.db` is created in the current directory at startup. It is seeded with:

- one expired RSA private key (exp <= now)
- one valid RSA private key (exp > now, ~1 hour)

## API Endpoints

- `GET /.well-known/jwks.json` - Get public keys
- `GET /jwks` - Alternative JWKS endpoint
- `POST /auth` - Get a JWT token
- `POST /auth?expired=true` - Sign with an expired key (for testing)

## Example Usage

```bash
# Get public keys
curl http://localhost:8080/.well-known/jwks.json

# Get a JWT token
curl -X POST http://localhost:8080/auth

# Get a JWT token signed with an expired key
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Notes

- All DB queries are parameterized to prevent SQL injection.
- Private keys are stored serialized as PKCS#1 PEM in the DB (BLOB column) and parsed when needed.
- For coverage on Windows, `cargo-llvm-cov` is recommended. Tarpaulin works best on Linux.

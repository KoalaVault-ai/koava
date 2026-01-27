//! Cryptographic key types
//!
//! This module contains data structures for cryptographic keys and algorithms.

use serde_json;

// ============================================================================
// Key Types
// ============================================================================

/// JSON Web Key (JWK) as defined in RFC 7517
///
/// JWK format varies by key type:
/// - `"oct"` (symmetric keys like AES): contains `k` (key material)
/// - `"okp"` (Ed25519): contains `x` (public key) and `d` (private key)
/// - `"RSA"`: contains `n` (modulus) and `e` (exponent)
/// - `"EC"`: contains `crv` (curve), `x`, `y` (coordinates)
///
/// Common fields: `kty` (key type), `alg` (algorithm), `kid` (key ID)
pub type Jwk = serde_json::Value;

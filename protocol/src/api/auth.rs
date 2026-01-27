//! Authentication API DTOs
//!
//! This module contains data transfer objects for authentication-related endpoints,
//! including login, token refresh, and API key management.

use serde::{Deserialize, Serialize};
use validator::Validate;

pub use crate::common::{Claims, LoginResponse};

// ============================================================================
// Login DTOs
// ============================================================================

/// API key-based login request for inference endpoints
/// API key format: sk-{random_chars}, typically 83 characters (sk- + 80 chars)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct InferenceLoginRequest {
    /// API key in format sk-{random_chars}, max 255 characters (database limit)
    #[validate(length(min = 10, max = 255))]
    pub api_key: String,
}

/// Inference login response
pub type InferenceLoginResponse = LoginResponse;

// ============================================================================
// Token Refresh DTOs
// ============================================================================

/// Refresh access token request
/// Refresh token format: rt-{random_chars}, typically 35 characters (rt- + 32 chars)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    /// Refresh token in format rt-{random_chars}, max 255 characters
    #[validate(length(min = 10, max = 255))]
    pub refresh_token: String,
}

/// Refresh token response
pub type RefreshTokenResponse = LoginResponse;

/// Revoke refresh token request
/// Refresh token format: rt-{random_chars}, typically 35 characters (rt- + 32 chars)
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RevokeRefreshTokenRequest {
    /// Refresh token in format rt-{random_chars}, max 255 characters
    #[validate(length(min = 10, max = 255))]
    pub refresh_token: String,
}

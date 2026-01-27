//! LoadPolicy type for encryption operations
//! This is a local copy since cryptotensors may not export LoadPolicy directly

use serde::{Deserialize, Serialize};

/// Policy for tensor model loading and remote KMS validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadPolicy {
    /// OPA policy content for tensor model loading validation
    #[serde(rename = "local")]
    local_policy: String,

    /// OPA policy content for KMS key release validation
    #[serde(rename = "remote")]
    remote_policy: String,
}

impl LoadPolicy {
    /// Create a new LoadPolicy
    pub fn new(local: Option<String>, remote: Option<String>) -> Self {
        let default_policy = "package model\nallow = true".to_string();
        Self {
            local_policy: local.unwrap_or_else(|| default_policy.clone()),
            remote_policy: remote.unwrap_or(default_policy),
        }
    }
}

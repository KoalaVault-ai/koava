//! Model API DTOs
//!
//! This module contains data transfer objects for model-related endpoints,
//! including model creation, management, file operations, and subscriptions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub use crate::common::{Jwk, Model, ModelDetail, ModelFile, ModelFileDetail};

// ============================================================================
// Model Management DTOs
// ============================================================================

/// Create model request
///
/// Used for POST /{username}/models endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateModelRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    #[validate(length(max = 10000))]
    pub description: Option<String>,
}

/// Create model response
///
/// Returns the created model with full details
pub type CreateModelResponse = ModelDetail;

// ============================================================================
// Model Key Management DTOs
// ============================================================================

/// Get model master key response
///
/// Response for GET /{username}/models/{model_name}/master-key endpoint
/// Note: This endpoint uses path parameters only, no request body needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetModelMasterKeyResponse {
    pub master_key_jwk: Jwk,
}

/// Get user sign key response
///
/// Response for GET /{username}/sign-key endpoint
/// Note: This endpoint uses path parameters only, no request body needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserSignKeyResponse {
    pub private_key_jwk: Jwk,
}

// ============================================================================
// Model File Management DTOs
// ============================================================================

/// List model files response
///
/// Response for GET /{username}/models/{model_name}/files endpoint
/// Note: This endpoint uses path parameters only, no request body needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFilesListResponse {
    pub model_id: Uuid,
    pub model_name: Option<String>,
    pub files: Vec<ModelFile>,
    pub total_count: usize,
}

/// Get single model file response
///
/// Response for GET /{username}/models/{model_name}/files/{filename} endpoint
/// Returns a single model file with full header data
/// Note: This endpoint uses path parameters only, no request body needed
pub type GetModelFileResponse = ModelFileDetail;

/// Upload single file header request
///
/// Used as part of UploadModelFilesRequest for POST /{username}/models/{model_name}/files endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UploadSingleFileHeaderRequest {
    #[validate(length(min = 1, max = 255))]
    pub filename: String,
    #[validate(length(min = 1, max = 10485760))] // Max 10MB for header
    pub file_header: String,
}

/// Upload model files request
///
/// Used for POST /{username}/models/{model_name}/files endpoint
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UploadModelFilesRequest {
    #[validate(length(min = 1, max = 100))] // Max 100 files per request
    #[validate(nested)]
    pub files: Vec<UploadSingleFileHeaderRequest>,
}

/// Upload model files response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadModelFilesResponse {
    pub total_uploaded: usize,
}


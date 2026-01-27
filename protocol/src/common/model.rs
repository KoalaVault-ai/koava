//! Model-related data structures
//!
//! This module contains data structures for models, including simple model representations,
//! subscribed models, and model file information.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Model Structures
// ============================================================================

/// Model representation for list views
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Model {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub description: Option<String>,
    pub published: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Detailed model representation
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelDetail {
    pub id: Uuid,
    pub model_name: String,
    pub username: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub published: bool,
    pub repository_url: Option<String>,
    pub readme_content: Option<String>,
    pub model_size: Option<String>,
    pub download_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Model File Structures
// ============================================================================

/// Model file representation for list views
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFile {
    pub id: Uuid,
    pub model_id: Uuid,
    pub filename: String,
    pub header_size: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Detailed model file representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFileDetail {
    pub id: Uuid,
    pub model_id: Uuid,
    pub filename: String,
    pub file_header: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

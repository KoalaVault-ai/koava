//! Unified error handling system for KoalaVault CLI and SDK
//!
//! This module provides a comprehensive error system with:
//! - Unique error codes for debugging and documentation
//! - Structured error information with context
//! - Convenient constructor methods
//! - Automatic conversions from common error types

use std::fmt;
use thiserror::Error;

/// Unified Result type for all KoalaVault operations
pub type Result<T> = std::result::Result<T, KoavaError>;

/// Error codes for KoalaVault operations
///
/// Each error has a unique code in the format `KXXX` where:
/// - K1XX: Authentication and authorization errors
/// - K2XX: Network and API errors
/// - K3XX: File and I/O errors
/// - K4XX: Configuration errors
/// - K5XX: Validation and input errors
/// - K6XX: Cryptography and key errors
/// - K7XX: Model and resource errors
/// - K8XX: UI and interaction errors
/// - K9XX: Internal errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Authentication (K1XX)
    /// K101: Authentication failed
    AuthenticationFailed,
    /// K102: Authorization denied
    AuthorizationDenied,
    /// K103: Token expired
    TokenExpired,
    /// K104: Invalid API key
    InvalidApiKey,
    /// K105: Session not found
    SessionNotFound,

    // Network (K2XX)
    /// K201: HTTP request failed
    HttpError,
    /// K202: Connection timeout
    ConnectionTimeout,
    /// K203: DNS resolution failed
    DnsError,
    /// K204: Connection refused
    ConnectionRefused,
    /// K205: API returned error response
    ApiError,
    /// K206: Invalid API response format
    InvalidResponse,

    // File/IO (K3XX)
    /// K301: File not found
    FileNotFound,
    /// K302: File read error
    FileReadError,
    /// K303: File write error
    FileWriteError,
    /// K304: Directory error
    DirectoryError,
    /// K305: Path error
    PathError,
    /// K306: File already exists
    FileAlreadyExists,

    // Configuration (K4XX)
    /// K401: Configuration error
    ConfigError,
    /// K402: Invalid endpoint URL
    InvalidEndpoint,
    /// K403: Missing configuration
    MissingConfig,
    /// K404: Certificate verification failed
    CertificateError,

    // Validation (K5XX)
    /// K501: Invalid input
    InvalidInput,
    /// K502: Validation failed
    ValidationFailed,
    /// K503: Model validation error
    ModelValidationError,
    /// K504: Format error
    FormatError,

    // Cryptography (K6XX)
    /// K601: Encryption failed
    EncryptionFailed,
    /// K602: Decryption failed
    DecryptionFailed,
    /// K603: Key generation failed
    KeyGenerationFailed,
    /// K604: Key not found
    KeyNotFound,
    /// K605: Invalid key format
    InvalidKeyFormat,

    // Model/Resource (K7XX)
    /// K701: Model not found
    ModelNotFound,
    /// K702: Model already exists
    ModelAlreadyExists,
    /// K703: Upload failed
    UploadFailed,
    /// K704: Download failed
    DownloadFailed,
    /// K705: Resource not found
    ResourceNotFound,
    /// K706: Deploy failed
    DeployFailed,
    /// K707: Attestation failed
    AttestationFailed,

    // UI (K8XX)
    /// K801: Dialog error
    DialogError,
    /// K802: User cancelled
    UserCancelled,
    /// K803: Display error
    DisplayError,

    // Internal (K9XX)
    /// K901: Internal error
    InternalError,
    /// K902: Serialization error
    SerializationError,
    /// K903: Unexpected state
    UnexpectedState,
}

impl ErrorCode {
    /// Get the numeric code
    pub fn code(&self) -> u16 {
        match self {
            // Authentication (K1XX)
            ErrorCode::AuthenticationFailed => 101,
            ErrorCode::AuthorizationDenied => 102,
            ErrorCode::TokenExpired => 103,
            ErrorCode::InvalidApiKey => 104,
            ErrorCode::SessionNotFound => 105,

            // Network (K2XX)
            ErrorCode::HttpError => 201,
            ErrorCode::ConnectionTimeout => 202,
            ErrorCode::DnsError => 203,
            ErrorCode::ConnectionRefused => 204,
            ErrorCode::ApiError => 205,
            ErrorCode::InvalidResponse => 206,

            // File/IO (K3XX)
            ErrorCode::FileNotFound => 301,
            ErrorCode::FileReadError => 302,
            ErrorCode::FileWriteError => 303,
            ErrorCode::DirectoryError => 304,
            ErrorCode::PathError => 305,
            ErrorCode::FileAlreadyExists => 306,

            // Configuration (K4XX)
            ErrorCode::ConfigError => 401,
            ErrorCode::InvalidEndpoint => 402,
            ErrorCode::MissingConfig => 403,
            ErrorCode::CertificateError => 404,

            // Validation (K5XX)
            ErrorCode::InvalidInput => 501,
            ErrorCode::ValidationFailed => 502,
            ErrorCode::ModelValidationError => 503,
            ErrorCode::FormatError => 504,

            // Cryptography (K6XX)
            ErrorCode::EncryptionFailed => 601,
            ErrorCode::DecryptionFailed => 602,
            ErrorCode::KeyGenerationFailed => 603,
            ErrorCode::KeyNotFound => 604,
            ErrorCode::InvalidKeyFormat => 605,

            // Model/Resource (K7XX)
            ErrorCode::ModelNotFound => 701,
            ErrorCode::ModelAlreadyExists => 702,
            ErrorCode::UploadFailed => 703,
            ErrorCode::DownloadFailed => 704,
            ErrorCode::ResourceNotFound => 705,
            ErrorCode::DeployFailed => 706,
            ErrorCode::AttestationFailed => 707,

            // UI (K8XX)
            ErrorCode::DialogError => 801,
            ErrorCode::UserCancelled => 802,
            ErrorCode::DisplayError => 803,

            // Internal (K9XX)
            ErrorCode::InternalError => 901,
            ErrorCode::SerializationError => 902,
            ErrorCode::UnexpectedState => 903,
        }
    }

    /// Get the string code (e.g., "K101")
    pub fn as_str(&self) -> String {
        format!("K{}", self.code())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "K{}", self.code())
    }
}

/// Main error type for all KoalaVault operations
#[derive(Error, Debug)]
pub enum KoavaError {
    // ==================== Authentication Errors (K1XX) ====================
    /// Authentication failed
    #[error("[{code}] Authentication failed: {message}")]
    Authentication {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Authorization denied
    #[error("[{code}] Authorization denied: {message}")]
    Authorization { code: ErrorCode, message: String },

    // ==================== Network Errors (K2XX) ====================
    /// HTTP/Network error
    #[error("[{code}] Network error: {message}")]
    Network {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<reqwest::Error>,
    },

    /// API error with status code
    #[error("[{code}] API error ({status}): {message}")]
    Api {
        code: ErrorCode,
        status: u16,
        message: String,
    },

    // ==================== File/IO Errors (K3XX) ====================
    /// File or IO error
    #[error("[{code}] {context}: {message}")]
    Io {
        code: ErrorCode,
        context: String,
        message: String,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Path related error
    #[error("[{code}] Path error: {message}")]
    Path {
        code: ErrorCode,
        message: String,
        path: Option<String>,
    },

    // ==================== Configuration Errors (K4XX) ====================
    /// Configuration error
    #[error("[{code}] Configuration error: {message}")]
    Config {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<config::ConfigError>,
    },

    // ==================== Validation Errors (K5XX) ====================
    /// Validation error
    #[error("[{code}] Validation error: {message}")]
    Validation {
        code: ErrorCode,
        message: String,
        field: Option<String>,
    },

    /// Invalid input error
    #[error("[{code}] Invalid input: {message}")]
    InvalidInput { code: ErrorCode, message: String },

    // ==================== Cryptography Errors (K6XX) ====================
    /// Cryptography error
    #[error("[{code}] Cryptography error: {message}")]
    Crypto { code: ErrorCode, message: String },

    /// Key management error
    #[error("[{code}] Key error: {message}")]
    Key { code: ErrorCode, message: String },

    // ==================== Model/Resource Errors (K7XX) ====================
    /// Resource not found
    #[error("[{code}] Not found: {resource}")]
    NotFound { code: ErrorCode, resource: String },

    /// Resource already exists
    #[error("[{code}] Already exists: {resource}")]
    AlreadyExists { code: ErrorCode, resource: String },

    /// Upload error
    #[error("[{code}] Upload failed: {message}")]
    Upload { code: ErrorCode, message: String },

    /// Model-specific error
    #[error("[{code}] Model error: {message}")]
    Model {
        code: ErrorCode,
        message: String,
        model_name: Option<String>,
    },

    /// Deployment error
    #[error("[{code}] Deployment error: {message}")]
    Deploy { code: ErrorCode, message: String },

    /// Attestation error
    #[error("[{code}] Attestation error: {message}")]
    Attestation { code: ErrorCode, message: String },

    // ==================== UI Errors (K8XX) ====================
    /// UI/Dialog error
    #[error("[{code}] UI error: {message}")]
    Ui { code: ErrorCode, message: String },

    // ==================== Internal Errors (K9XX) ====================
    /// Internal/Unexpected error
    #[error("[{code}] Internal error: {message}")]
    Internal { code: ErrorCode, message: String },

    /// JSON serialization error
    #[error("[{code}] Serialization error: {message}")]
    Serialization {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<serde_json::Error>,
    },

    /// Timeout error
    #[error("[K202] Operation timed out")]
    Timeout,
}

// ==================== Constructor Methods ====================

impl KoavaError {
    // --- Authentication ---

    /// Create authentication error
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            code: ErrorCode::AuthenticationFailed,
            message: message.into(),
            source: None,
        }
    }

    /// Create authentication error with source
    pub fn authentication_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Authentication {
            code: ErrorCode::AuthenticationFailed,
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create token expired error
    pub fn token_expired(message: impl Into<String>) -> Self {
        Self::Authentication {
            code: ErrorCode::TokenExpired,
            message: message.into(),
            source: None,
        }
    }

    /// Create authorization error
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Authorization {
            code: ErrorCode::AuthorizationDenied,
            message: message.into(),
        }
    }

    // --- Network ---

    /// Create network error from message
    pub fn network(message: impl Into<String>) -> Self {
        Self::Network {
            code: ErrorCode::HttpError,
            message: message.into(),
            source: None,
        }
    }

    /// Create network error from reqwest error
    pub fn network_from_reqwest(err: reqwest::Error) -> Self {
        let code = if err.is_timeout() {
            ErrorCode::ConnectionTimeout
        } else if err.is_connect() {
            ErrorCode::ConnectionRefused
        } else {
            ErrorCode::HttpError
        };

        Self::Network {
            code,
            message: err.to_string(),
            source: Some(err),
        }
    }

    /// Create API error
    pub fn api(status: u16, message: impl Into<String>) -> Self {
        Self::Api {
            code: ErrorCode::ApiError,
            status,
            message: message.into(),
        }
    }

    /// Create invalid response error
    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self::Api {
            code: ErrorCode::InvalidResponse,
            status: 0,
            message: message.into(),
        }
    }

    // --- File/IO ---

    /// Create IO error with context
    pub fn io(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Io {
            code: ErrorCode::FileReadError,
            context: context.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Create IO error from std::io::Error
    pub fn io_from_error(context: impl Into<String>, err: std::io::Error) -> Self {
        let code = match err.kind() {
            std::io::ErrorKind::NotFound => ErrorCode::FileNotFound,
            std::io::ErrorKind::PermissionDenied => ErrorCode::FileWriteError,
            std::io::ErrorKind::AlreadyExists => ErrorCode::FileAlreadyExists,
            _ => ErrorCode::FileReadError,
        };

        Self::Io {
            code,
            context: context.into(),
            message: err.to_string(),
            source: Some(err),
        }
    }

    /// Create file not found error
    pub fn file_not_found(path: impl Into<String>) -> Self {
        let path_str = path.into();
        Self::Io {
            code: ErrorCode::FileNotFound,
            context: "File not found".to_string(),
            message: path_str.clone(),
            source: None,
        }
    }

    /// Create path error
    pub fn path(message: impl Into<String>) -> Self {
        Self::Path {
            code: ErrorCode::PathError,
            message: message.into(),
            path: None,
        }
    }

    /// Create path error with path
    pub fn path_with_location(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self::Path {
            code: ErrorCode::PathError,
            message: message.into(),
            path: Some(path.into()),
        }
    }

    // --- Configuration ---

    /// Create configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            code: ErrorCode::ConfigError,
            message: message.into(),
            source: None,
        }
    }

    /// Create configuration error with source
    pub fn config_from_error(err: config::ConfigError) -> Self {
        Self::Config {
            code: ErrorCode::ConfigError,
            message: err.to_string(),
            source: Some(err),
        }
    }

    /// Create certificate error
    pub fn certificate(message: impl Into<String>) -> Self {
        Self::Config {
            code: ErrorCode::CertificateError,
            message: message.into(),
            source: None,
        }
    }

    // --- Validation ---

    /// Create validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            code: ErrorCode::ValidationFailed,
            message: message.into(),
            field: None,
        }
    }

    /// Create validation error with field
    pub fn validation_field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self::Validation {
            code: ErrorCode::ValidationFailed,
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create model validation error
    pub fn model_validation(message: impl Into<String>) -> Self {
        Self::Validation {
            code: ErrorCode::ModelValidationError,
            message: message.into(),
            field: None,
        }
    }

    /// Create invalid input error
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            code: ErrorCode::InvalidInput,
            message: message.into(),
        }
    }

    // --- Cryptography ---

    /// Create crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::EncryptionFailed,
            message: message.into(),
        }
    }

    /// Create key error
    pub fn key(message: impl Into<String>) -> Self {
        Self::Key {
            code: ErrorCode::KeyNotFound,
            message: message.into(),
        }
    }

    /// Create key generation error
    pub fn key_generation(message: impl Into<String>) -> Self {
        Self::Key {
            code: ErrorCode::KeyGenerationFailed,
            message: message.into(),
        }
    }

    // --- Model/Resource ---

    /// Create not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound {
            code: ErrorCode::ResourceNotFound,
            resource: resource.into(),
        }
    }

    /// Create model not found error
    pub fn model_not_found(model: impl Into<String>) -> Self {
        Self::NotFound {
            code: ErrorCode::ModelNotFound,
            resource: model.into(),
        }
    }

    /// Create already exists error
    pub fn already_exists(resource: impl Into<String>) -> Self {
        Self::AlreadyExists {
            code: ErrorCode::ModelAlreadyExists,
            resource: resource.into(),
        }
    }

    /// Create upload error
    pub fn upload(message: impl Into<String>) -> Self {
        Self::Upload {
            code: ErrorCode::UploadFailed,
            message: message.into(),
        }
    }

    /// Create model error
    pub fn model(message: impl Into<String>) -> Self {
        Self::Model {
            code: ErrorCode::ModelValidationError,
            message: message.into(),
            model_name: None,
        }
    }

    /// Create model error with name
    pub fn model_with_name(message: impl Into<String>, model_name: impl Into<String>) -> Self {
        Self::Model {
            code: ErrorCode::ModelValidationError,
            message: message.into(),
            model_name: Some(model_name.into()),
        }
    }

    /// Create deployment error
    pub fn deploy(message: impl Into<String>) -> Self {
        Self::Deploy {
            code: ErrorCode::DeployFailed,
            message: message.into(),
        }
    }

    /// Create attestation error
    pub fn attestation(message: impl Into<String>) -> Self {
        Self::Attestation {
            code: ErrorCode::AttestationFailed,
            message: message.into(),
        }
    }

    // --- UI ---

    /// Create UI error
    pub fn ui(message: impl Into<String>) -> Self {
        Self::Ui {
            code: ErrorCode::DialogError,
            message: message.into(),
        }
    }

    /// Create user cancelled error
    pub fn user_cancelled() -> Self {
        Self::Ui {
            code: ErrorCode::UserCancelled,
            message: "Operation cancelled by user".to_string(),
        }
    }

    // --- Internal ---

    /// Create internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            code: ErrorCode::InternalError,
            message: message.into(),
        }
    }

    /// Create serialization error
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            code: ErrorCode::SerializationError,
            message: message.into(),
            source: None,
        }
    }

    // --- Utility Methods ---

    /// Get the error code
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authentication { code, .. } => *code,
            Self::Authorization { code, .. } => *code,
            Self::Network { code, .. } => *code,
            Self::Api { code, .. } => *code,
            Self::Io { code, .. } => *code,
            Self::Path { code, .. } => *code,
            Self::Config { code, .. } => *code,
            Self::Validation { code, .. } => *code,
            Self::InvalidInput { code, .. } => *code,
            Self::Crypto { code, .. } => *code,
            Self::Key { code, .. } => *code,
            Self::NotFound { code, .. } => *code,
            Self::AlreadyExists { code, .. } => *code,
            Self::Upload { code, .. } => *code,
            Self::Model { code, .. } => *code,
            Self::Deploy { code, .. } => *code,
            Self::Attestation { code, .. } => *code,
            Self::Ui { code, .. } => *code,
            Self::Internal { code, .. } => *code,
            Self::Serialization { code, .. } => *code,
            Self::Timeout => ErrorCode::ConnectionTimeout,
        }
    }

    /// Check if this is an authentication error
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::Authentication { .. } | Self::Authorization { .. }
        )
    }

    /// Check if this is a network error
    pub fn is_network_error(&self) -> bool {
        matches!(
            self,
            Self::Network { .. } | Self::Api { .. } | Self::Timeout
        )
    }

    /// Check if this is a retryable error
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network { .. }
                | Self::Timeout
                | Self::Api { status: 503, .. }
                | Self::Api { status: 429, .. }
        )
    }
}

// ==================== From Implementations ====================

impl From<std::io::Error> for KoavaError {
    fn from(err: std::io::Error) -> Self {
        Self::io_from_error("IO operation", err)
    }
}

impl From<reqwest::Error> for KoavaError {
    fn from(err: reqwest::Error) -> Self {
        Self::network_from_reqwest(err)
    }
}

impl From<serde_json::Error> for KoavaError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization {
            code: ErrorCode::SerializationError,
            message: err.to_string(),
            source: Some(err),
        }
    }
}

impl From<config::ConfigError> for KoavaError {
    fn from(err: config::ConfigError) -> Self {
        Self::config_from_error(err)
    }
}

impl From<dialoguer::Error> for KoavaError {
    fn from(err: dialoguer::Error) -> Self {
        Self::Ui {
            code: ErrorCode::DialogError,
            message: format!("Dialog error: {}", err),
        }
    }
}

impl From<std::path::StripPrefixError> for KoavaError {
    fn from(err: std::path::StripPrefixError) -> Self {
        Self::Path {
            code: ErrorCode::PathError,
            message: format!("Path strip prefix error: {}", err),
            path: None,
        }
    }
}

// Manual Clone implementation that drops non-cloneable sources
impl Clone for KoavaError {
    fn clone(&self) -> Self {
        match self {
            Self::Authentication {
                code,
                message,
                source: _,
            } => Self::Authentication {
                code: *code,
                message: message.clone(),
                source: None,
            },
            Self::Authorization { code, message } => Self::Authorization {
                code: *code,
                message: message.clone(),
            },
            Self::Network {
                code,
                message,
                source: _,
            } => Self::Network {
                code: *code,
                message: message.clone(),
                source: None,
            },
            Self::Api {
                code,
                status,
                message,
            } => Self::Api {
                code: *code,
                status: *status,
                message: message.clone(),
            },
            Self::Io {
                code,
                context,
                message,
                source: _,
            } => Self::Io {
                code: *code,
                context: context.clone(),
                message: message.clone(),
                source: None,
            },
            Self::Path {
                code,
                message,
                path,
            } => Self::Path {
                code: *code,
                message: message.clone(),
                path: path.clone(),
            },
            Self::Config {
                code,
                message,
                source: _,
            } => Self::Config {
                code: *code,
                message: message.clone(),
                source: None,
            },
            Self::Validation {
                code,
                message,
                field,
            } => Self::Validation {
                code: *code,
                message: message.clone(),
                field: field.clone(),
            },
            Self::InvalidInput { code, message } => Self::InvalidInput {
                code: *code,
                message: message.clone(),
            },
            Self::Crypto { code, message } => Self::Crypto {
                code: *code,
                message: message.clone(),
            },
            Self::Key { code, message } => Self::Key {
                code: *code,
                message: message.clone(),
            },
            Self::NotFound { code, resource } => Self::NotFound {
                code: *code,
                resource: resource.clone(),
            },
            Self::AlreadyExists { code, resource } => Self::AlreadyExists {
                code: *code,
                resource: resource.clone(),
            },
            Self::Upload { code, message } => Self::Upload {
                code: *code,
                message: message.clone(),
            },
            Self::Model {
                code,
                message,
                model_name,
            } => Self::Model {
                code: *code,
                message: message.clone(),
                model_name: model_name.clone(),
            },
            Self::Deploy { code, message } => Self::Deploy {
                code: *code,
                message: message.clone(),
            },
            Self::Attestation { code, message } => Self::Attestation {
                code: *code,
                message: message.clone(),
            },
            Self::Ui { code, message } => Self::Ui {
                code: *code,
                message: message.clone(),
            },
            Self::Internal { code, message } => Self::Internal {
                code: *code,
                message: message.clone(),
            },
            Self::Serialization {
                code,
                message,
                source: _,
            } => Self::Serialization {
                code: *code,
                message: message.clone(),
                source: None,
            },
            Self::Timeout => Self::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(ErrorCode::AuthenticationFailed.code(), 101);
        assert_eq!(ErrorCode::HttpError.code(), 201);
        assert_eq!(ErrorCode::FileNotFound.code(), 301);
        assert_eq!(ErrorCode::ConfigError.code(), 401);
    }

    #[test]
    fn test_error_code_string() {
        assert_eq!(ErrorCode::AuthenticationFailed.as_str(), "K101");
        assert_eq!(ErrorCode::HttpError.as_str(), "K201");
    }

    #[test]
    fn test_error_display() {
        let err = KoavaError::authentication("Invalid credentials");
        assert!(err.to_string().contains("K101"));
        assert!(err.to_string().contains("Invalid credentials"));
    }

    #[test]
    fn test_error_is_retryable() {
        let timeout = KoavaError::Timeout;
        assert!(timeout.is_retryable());

        let auth_err = KoavaError::authentication("Failed");
        assert!(!auth_err.is_retryable());
    }
}

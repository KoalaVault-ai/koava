//! Error types for koava CLI and SDK

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConverterError>;

#[derive(Error, Debug)]
pub enum ConverterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Model validation error: {0}")]
    ModelValidation(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Upload error: {0}")]
    Upload(String),

    #[error("SDK error: {0}")]
    Sdk(#[from] ClientError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Path error: {0}")]
    Path(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("File error: {0}")]
    File(String),

    #[error("UI error: {0}")]
    Ui(String),

    #[error("Config error: {0}")]
    ConfigError(#[from] config::ConfigError),
}

impl ConverterError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn file(msg: impl Into<String>) -> Self {
        Self::File(msg.into())
    }

    pub fn ui(msg: impl Into<String>) -> Self {
        Self::Ui(msg.into())
    }
}

impl From<dialoguer::Error> for ConverterError {
    fn from(err: dialoguer::Error) -> Self {
        Self::Ui(format!("Dialog error: {}", err))
    }
}

impl From<std::path::StripPrefixError> for ConverterError {
    fn from(err: std::path::StripPrefixError) -> Self {
        Self::Path(format!("Path strip prefix error: {}", err))
    }
}

/// Main error type for the SDK components
#[derive(Error, Debug)]
pub enum ClientError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Authentication failed
    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    /// Authorization failed
    #[error("Authorization failed: {message}")]
    Authorization { message: String },

    /// API error
    #[error("API error: {status_code} - {message}")]
    Api { status_code: u16, message: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptography error
    #[error("Cryptography error: {message}")]
    Crypto { message: String },

    /// Invalid input error
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Resource not found error
    #[error("Not found: {resource}")]
    NotFound { resource: String },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// Key management error
    #[error("Key error: {message}")]
    Key { message: String },

    /// File operation error
    #[error("File error: {message}")]
    File { message: String },
}

impl ClientError {
    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    pub fn authorization<S: Into<String>>(message: S) -> Self {
        Self::Authorization {
            message: message.into(),
        }
    }

    pub fn api(status_code: u16, message: String) -> Self {
        Self::Api {
            status_code,
            message,
        }
    }

    pub fn crypto<S: Into<String>>(message: S) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn key<S: Into<String>>(message: S) -> Self {
        Self::Key {
            message: message.into(),
        }
    }

    pub fn file<S: Into<String>>(message: S) -> Self {
        Self::File {
            message: message.into(),
        }
    }
}

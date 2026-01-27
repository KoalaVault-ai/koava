//! Test utilities and helpers for unit tests
//!
//! This module provides common testing utilities including:
//! - Mock implementations
//! - Test data generators
//! - Helper functions for creating test fixtures

#[cfg(test)]
pub mod test_helpers {
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Create a temporary directory for testing
    pub fn create_temp_dir() -> TempDir {
        tempfile::tempdir().expect("Failed to create temp dir")
    }

    /// Create a temporary file with content
    pub fn create_temp_file_with_content(dir: &TempDir, filename: &str, content: &[u8]) -> PathBuf {
        let file_path = dir.path().join(filename);
        std::fs::write(&file_path, content).expect("Failed to write temp file");
        file_path
    }

    /// Create a mock safetensors header
    pub fn create_mock_safetensors_header() -> Vec<u8> {
        let header_json = r#"{"__metadata__":{},"weight1":{"dtype":"F32","shape":[10,20],"data_offsets":[0,800]}}"#;
        let header_len = header_json.len() as u64;
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&header_len.to_le_bytes());
        header_data.extend_from_slice(header_json.as_bytes());
        header_data
    }

    /// Create a mock encrypted safetensors header
    pub fn create_mock_encrypted_safetensors_header() -> Vec<u8> {
        let header_json = r#"{"__metadata__":{"__encryption__":{"algorithm":"AES-256-GCM"}},"weight1":{"dtype":"F32","shape":[10,20],"data_offsets":[0,800]}}"#;
        let header_len = header_json.len() as u64;
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&header_len.to_le_bytes());
        header_data.extend_from_slice(header_json.as_bytes());
        header_data
    }

    /// Create a complete mock safetensors file
    pub fn create_mock_safetensors_file(dir: &TempDir, filename: &str, encrypted: bool) -> PathBuf {
        let header = if encrypted {
            create_mock_encrypted_safetensors_header()
        } else {
            create_mock_safetensors_header()
        };

        // Add some dummy tensor data
        let mut file_content = header;
        file_content.extend_from_slice(&vec![0u8; 800]); // Dummy tensor data

        create_temp_file_with_content(dir, filename, &file_content)
    }
}

use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::{KoavaError, Result};
use crate::policy::LoadPolicy;
use crate::utils::{format_bytes, CryptoUtils};
use cryptotensors::KeyMaterial;
use cryptotensors::SerializeCryptoConfig;
use cryptotensors::{serialize_to_file, AccessPolicy, SafeTensors};
use std::collections::HashMap;

/// Represents a model directory containing safetensors files
#[derive(Debug, Clone)]
pub struct ModelDirectory {
    /// Path to the model directory
    pub path: PathBuf,

    /// List of all safetensors files found
    pub all_files: Vec<ModelFile>,

    /// List of unencrypted safetensors files
    pub unencrypted_files: Vec<ModelFile>,

    /// List of encrypted safetensors files
    pub encrypted_files: Vec<ModelFile>,

    /// Total size in bytes
    pub total_size: u64,
}

/// Information about a model file
#[derive(Debug, Clone)]
pub struct ModelFile {
    /// Filename
    pub name: String,

    /// Full path to file
    pub path: PathBuf,

    /// File size in bytes
    pub size: u64,

    /// Whether the file is already encrypted
    pub is_encrypted: bool,
}

impl ModelDirectory {
    /// Scan a model directory and find all safetensors files
    pub async fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(KoavaError::file_not_found(path.display().to_string()));
        }

        if !path.is_dir() {
            return Err(KoavaError::io(
                "Directory validation",
                format!("Path is not a directory: {}", path.display()),
            ));
        }

        let mut all_files = Vec::new();
        let mut total_size = 0u64;

        // Simple directory scanning - process only the model directory itself
        let mut entries = tokio::fs::read_dir(path).await.map_err(|e| {
            KoavaError::io(
                "Directory scan",
                format!("Failed to read directory: {}", e),
            )
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            KoavaError::io(
                "Directory entry",
                format!("Failed to read directory entry: {}", e),
            )
        })? {
            let file_type = entry.file_type().await.map_err(|e| {
                KoavaError::io("File type", format!("Failed to get file type: {}", e))
            })?;

            if file_type.is_file() {
                let file_path = entry.path();

                // Check if it's a safetensors or cryptotensors file
                if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_lowercase();
                    if ext_lower == "safetensors" || ext_lower == "cryptotensors" {
                        match ModelFile::from_path(&file_path).await {
                            Ok(model_file) => {
                                let size = model_file.size;
                                let _name = model_file.name.clone();
                                let _is_encrypted = model_file.is_encrypted;
                                total_size += size;
                                all_files.push(model_file);
                            }
                            Err(_e) => {
                                // Skip files that can't be parsed
                            }
                        }
                    }
                }
            }
        }

        if all_files.is_empty() {
            return Err(KoavaError::validation(
                "No safetensors or cryptotensors files found in model directory",
            ));
        }

        // Pre-calculate encrypted and unencrypted file lists
        let mut unencrypted_files = Vec::new();
        let mut encrypted_files = Vec::new();

        for file in &all_files {
            if file.is_encrypted {
                encrypted_files.push(file.clone());
            } else {
                unencrypted_files.push(file.clone());
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            all_files,
            unencrypted_files,
            encrypted_files,
            total_size,
        })
    }

    /// Get all unencrypted safetensors files
    pub fn get_unencrypted_files(&self) -> &[ModelFile] {
        &self.unencrypted_files
    }

    /// Get all encrypted files
    pub fn get_encrypted_files(&self) -> &[ModelFile] {
        &self.encrypted_files
    }

    /// Get all files
    pub fn get_all_files(&self) -> &[ModelFile] {
        &self.all_files
    }

    /// Check if all files are encrypted
    pub fn is_fully_encrypted(&self) -> bool {
        self.unencrypted_files.is_empty()
    }

    /// Get formatted size string
    pub fn formatted_size(&self) -> String {
        format_bytes(self.total_size)
    }
}

impl ModelFile {
    /// Parse a model file and determine if it's encrypted
    pub async fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() || !path.is_file() {
            return Err(KoavaError::file_not_found(path.display().to_string()));
        }

        let metadata = fs::metadata(path).await?;
        let size = metadata.len();

        // Check if file is encrypted by attempting to parse it
        let is_encrypted = CryptoUtils::detect_safetensors_encryption(path).await?;

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            name: filename,
            path: path.to_path_buf(),
            size,
            is_encrypted,
        })
    }

    /// Get formatted size string
    pub fn formatted_size(&self) -> String {
        format_bytes(self.size)
    }
}

/// Encrypt a safetensors file using CryptoTensors
/// This function uses the library's serialize_to_file function which handles
/// metadata and tensor extraction internally via SafeTensors::deserialize
pub async fn encrypt_safetensors_file(
    input_path: &Path,
    output_path: &Path,
    enc_key_jwk: &serde_json::Value,
    sign_key_jwk: &serde_json::Value,
    policy: &LoadPolicy,
) -> Result<()> {
    // Convert JWK to KeyMaterial
    let enc_key = KeyMaterial::from_jwk(enc_key_jwk, false)
        .map_err(|e| KoavaError::crypto(format!("Failed to parse encryption key JWK: {}", e)))?;
    let sign_key = KeyMaterial::from_jwk(sign_key_jwk, false)
        .map_err(|e| KoavaError::crypto(format!("Failed to parse signing key JWK: {}", e)))?;

    // Read the input file
    let file_content = fs::read(input_path).await?;

    // Deserialize the safetensors file to get all tensor data
    // The library handles metadata extraction internally
    let safetensors = SafeTensors::deserialize(&file_content).map_err(|e| {
        KoavaError::io(
            "Safetensors parsing",
            format!("Failed to deserialize: {}", e),
        )
    })?;

    // Extract original metadata (e.g., framework, format, etc.) to preserve in the new file
    // Parse metadata from the file header since the library doesn't expose a metadata() method
    let original_metadata = extract_metadata_from_header(&file_content)?;

    // Convert LoadPolicy to AccessPolicy for SerializeCryptoConfig
    // Both have the same structure, so we can serialize and deserialize
    let policy_json = serde_json::to_value(policy)
        .map_err(|e| KoavaError::serialization(format!("Failed to serialize policy: {}", e)))?;
    let access_policy: AccessPolicy = serde_json::from_value(policy_json).map_err(|e| {
        KoavaError::serialization(format!("Failed to convert policy to AccessPolicy: {}", e))
    })?;

    // Create encryption configuration using with_keys and builder pattern
    let crypto_config = SerializeCryptoConfig::with_keys(enc_key, sign_key).policy(access_policy);

    // Extract all tensors from the deserialized file
    // The library's tensors() method returns Vec<(String, TensorView<'data>)>
    let tensor_views = safetensors.tensors();

    // Serialize with encryption - the library handles all metadata and encryption internally
    serialize_to_file(
        tensor_views.into_iter(),
        original_metadata,
        output_path,
        Some(&crypto_config),
    )
    .map_err(|e| KoavaError::crypto(format!("Failed to encrypt file: {}", e)))?;

    Ok(())
}

/// Extract non-reserved metadata from safetensors file header
/// This parses the JSON header and filters out reserved fields (starting with "__")
fn extract_metadata_from_header(file_content: &[u8]) -> Result<Option<HashMap<String, String>>> {
    // Read header length
    if file_content.len() < CryptoUtils::HEADER_LENGTH_SIZE {
        return Ok(None);
    }

    let header_len = u64::from_le_bytes(
        file_content[..CryptoUtils::HEADER_LENGTH_SIZE]
            .try_into()
            .map_err(|_| KoavaError::io("Header parsing", "Invalid header length"))?,
    ) as usize;

    if file_content.len() < CryptoUtils::HEADER_LENGTH_SIZE + header_len {
        return Ok(None);
    }

    // Parse JSON header
    let header_bytes = &file_content
        [CryptoUtils::HEADER_LENGTH_SIZE..CryptoUtils::HEADER_LENGTH_SIZE + header_len];
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| KoavaError::io("Header parsing", format!("Invalid UTF-8: {}", e)))?;

    let header_json: serde_json::Value = serde_json::from_str(header_str)
        .map_err(|e| KoavaError::serialization(format!("Invalid JSON in header: {}", e)))?;

    // Extract __metadata__ field if present
    if let Some(metadata_obj) = header_json.get(CryptoUtils::METADATA_KEY) {
        if let Some(metadata_map) = metadata_obj.as_object() {
            // Filter out reserved fields (starting with "__")
            let mut filtered_metadata = HashMap::new();
            for (key, value) in metadata_map {
                if !key.starts_with("__") {
                    if let Some(str_value) = value.as_str() {
                        filtered_metadata.insert(key.clone(), str_value.to_string());
                    }
                }
            }
            return Ok(if filtered_metadata.is_empty() {
                None
            } else {
                Some(filtered_metadata)
            });
        }
    }

    Ok(None)
}

// ── Model Service for CLI commands ─────────────────────────────────────────
use crate::client::ApiClient;
use crate::ui::UI;
use crate::upload::UploadService;
use crate::{CreateArgs, ListArgs, ModelFileService, RemoveArgs, UploadArgs};
use dialoguer::{theme::ColorfulTheme, Confirm};
use koalavault_protocol::api::{CreateModelRequest, CreateModelResponse};
use std::sync::Arc;

/// Model service for CLI commands
pub struct ModelService {
    ui: UI,
}

impl ModelService {
    /// Create a new model service
    pub fn new() -> Self {
        Self { ui: UI::new() }
    }

    /// Create a new model on server
    pub async fn create<C: ApiClient + ?Sized>(
        &self,
        client: Arc<C>,
        args: CreateArgs,
    ) -> Result<()> {
        // Display header
        self.ui.header("Create Model");
        self.ui.info(&format!("Model name: {}", args.name));
        if let Some(desc) = &args.description {
            self.ui.info(&format!("Description: {}", desc));
        }
        self.ui.separator();

        // Get current username from authenticated client
        let username = client.get_current_username().ok_or_else(|| {
            KoavaError::authentication("Failed to get current username".to_string())
        })?;

        // Prepare the request body using CreateModelRequest from protocol
        let request = CreateModelRequest {
            name: args.name.clone(),
            description: args.description.clone(),
        };

        // Make the API request using the correct endpoint: /api/resources/{username}/models
        let endpoint = format!("resources/{}/models", username);
        let response: crate::ApiResponse<CreateModelResponse> = client
            .authenticated_request(reqwest::Method::POST, &endpoint, Some(&request))
            .await
            .map_err(|e| {
                self.ui.error(&format!("Failed to create model: {}", e));
                e
            })?;

        // The response is already parsed as ApiResponse<CreateModelResponse>
        if let Some(model_data) = response.data {
            // Extract model information and build the model URL
            let model_url = format!(
                "https://www.koalavault.ai/{}/{}",
                model_data.username, model_data.model_name
            );
            self.ui.status("Create", "Success", true);
            self.ui
                .success(&format!("Model '{}' created successfully!", args.name));
            self.ui.info(&format!("Model URL: {}", model_url));

            Ok(())
        } else {
            let error_message = response
                .error
                .or(response.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            self.ui
                .error(&format!("Failed to create model: {}", error_message));
            Err(KoavaError::config(error_message))
        }
    }

    /// List files for a model on server
    pub async fn list<C: ApiClient + ?Sized>(&self, client: Arc<C>, args: ListArgs) -> Result<()> {
        // Parse model identifier: support both 'username/modelname' and 'modelname' formats
        let (username, model_name) = if args.model_identifier.contains('/') {
            let parts: Vec<&str> = args.model_identifier.split('/').collect();
            if parts.len() != 2 {
                return Err(KoavaError::upload(
                    "Invalid model identifier format. Use 'username/modelname' or just 'modelname'"
                        .to_string(),
                ));
            }
            let (provided_username, model_name) = (parts[0], parts[1]);

            // Get current user's username to check if they're trying to access someone else's model
            let current_username = client
                .get_current_username()
                .ok_or_else(|| KoavaError::authentication("Failed to get current username"))?
                .clone();

            if provided_username != current_username {
                return Err(KoavaError::upload(
                    "You can only list files for your own models".to_string(),
                ));
            }

            (provided_username.to_string(), model_name.to_string())
        } else {
            // Just modelname provided, use current user
            let current_username = client
                .get_current_username()
                .ok_or_else(|| KoavaError::authentication("Failed to get current username"))?
                .clone();
            (current_username, args.model_identifier.clone())
        };

        // Display header
        self.ui.header("Model Files");
        self.ui.info(&format!("Model: {}/{}", username, model_name));
        self.ui.separator();

        // Use SDK to list model files
        let file_service = ModelFileService::new(&*client);

        match file_service.list_model_files(&username, &model_name).await {
            Ok(files) => {
                if files.is_empty() {
                    self.ui.info("No files found for this model.");
                    return Ok(());
                }

                // Display files using box_content
                let file_lines: Vec<String> = files
                    .iter()
                    .map(|file| {
                        format!(
                            "{} ({})",
                            file.filename,
                            file.created_at.as_deref().unwrap_or("unknown")
                        )
                    })
                    .collect();

                self.ui.box_content(
                    &format!(
                        "Files for {}/{} ({} files)",
                        username,
                        model_name,
                        files.len()
                    ),
                    file_lines,
                );
                Ok(())
            }
            Err(e) => {
                self.ui.blank_line();
                self.ui.error(&format!("Failed to list files: {}", e));
                Err(KoavaError::upload(format!("Failed to list files: {}", e)))
            }
        }
    }

    /// Remove model files from server
    pub async fn remove<C: ApiClient + ?Sized>(
        &self,
        client: Arc<C>,
        args: RemoveArgs,
    ) -> Result<()> {
        // Parse model identifier: support both 'username/modelname' and 'modelname' formats
        let (username, model_name) = if args.model_identifier.contains('/') {
            let parts: Vec<&str> = args.model_identifier.split('/').collect();
            if parts.len() != 2 {
                return Err(KoavaError::upload(
                    "Invalid model identifier format. Use 'username/modelname' or just 'modelname'"
                        .to_string(),
                ));
            }
            let (provided_username, model_name) = (parts[0], parts[1]);

            // Get current user's username to check if they're trying to access someone else's model
            let current_username = client
                .get_current_username()
                .ok_or_else(|| KoavaError::authentication("Failed to get current username"))?
                .clone();

            if provided_username != current_username {
                return Err(KoavaError::authorization(
                    "You can only remove files from your own models",
                ));
            }

            (provided_username.to_string(), model_name.to_string())
        } else {
            // Just modelname provided, use current user
            let current_username = client
                .get_current_username()
                .ok_or_else(|| KoavaError::authentication("Failed to get current username"))?
                .clone();
            (current_username, args.model_identifier.clone())
        };

        // Confirm removal unless force is specified
        if !args.force {
            let should_remove = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "Are you sure you want to remove all files for model '{}/{}' from server?",
                    username, model_name
                ))
                .default(false)
                .interact()
                .map_err(|_| KoavaError::ui("Failed to read confirmation"))?;

            if !should_remove {
                self.ui.info("Removal cancelled.");
                return Ok(());
            }
        }

        // Use SDK to delete all model files
        let file_service = ModelFileService::new(&*client);

        match file_service
            .delete_all_model_files(&username, &model_name)
            .await
        {
            Ok(_) => {
                self.ui.blank_line();
                self.ui.status("Removal", "Success", true);
                self.ui.success(&format!(
                    "Successfully removed all files for model {}/{}",
                    username, model_name
                ));
                Ok(())
            }
            Err(e) => {
                self.ui.blank_line();
                self.ui
                    .error(&format!("Failed to remove model files: {}", e));
                Err(KoavaError::upload(format!(
                    "Failed to remove model files: {}",
                    e
                )))
            }
        }
    }

    /// Upload encrypted model to server
    pub async fn upload<C: ApiClient + ?Sized>(
        &self,
        client: Arc<C>,
        args: UploadArgs,
    ) -> Result<()> {
        // Display header
        self.ui.header("Upload Model");

        // Validate and scan model directory
        self.ui.info(&format!(
            "Scanning encrypted model directory: {}",
            args.model_path.display()
        ));

        // Use ModelDirectory instead of HuggingFaceModel to check encryption status
        let model_dir = crate::ModelDirectory::from_path(&args.model_path).await?;

        // Check if model is fully encrypted
        if !model_dir.is_fully_encrypted() {
            let unencrypted_files = model_dir.get_unencrypted_files();
            let file_names: Vec<String> =
                unencrypted_files.iter().map(|f| f.name.clone()).collect();
            self.ui
                .box_content("Model contains unencrypted files", file_names);
            self.ui
                .info("Please encrypt the model first using: koava encrypt <MODEL_PATH>");
            return Err(KoavaError::validation("Model is not fully encrypted"));
        }

        // Get model name from directory or use provided name
        let model_name = if let Some(name) = &args.name {
            name.clone()
        } else {
            use std::path::Component;

            let basename_from = |p: &Path| -> Option<String> {
                p.components().rev().find_map(|c| match c {
                    Component::Normal(s) => s.to_str().map(|s| s.to_string()),
                    _ => None,
                })
            };

            // Canonicalize path to handle "." case
            match model_dir.path.canonicalize() {
                Ok(canonical_path) => basename_from(canonical_path.as_path())
                    .unwrap_or_else(|| "unknown-model".to_string()),
                Err(_) => {
                    // Fallback to file_name if canonicalize fails
                    model_dir
                        .path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown-model".to_string())
                }
            }
        };

        // Get current username for display
        let username = client.get_current_username().ok_or_else(|| {
            KoavaError::authentication("Failed to get current username".to_string())
        })?;

        // Display model information
        let full_model_name = format!("{}/{}", username, model_name);

        // Display model summary
        self.ui.separator();
        self.ui.info(&format!("Model: {}", full_model_name));
        self.ui.info(&format!(
            "Total Size: {}",
            crate::ui::format_size_colored(model_dir.total_size)
        ));
        self.ui
            .info(&format!("Files: {}", model_dir.get_encrypted_files().len()));
        self.ui.separator();

        // Create upload service and start upload
        let upload_service = UploadService::new(client, true); // Enable progress bars

        self.ui.info("Uploading encrypted model...");
        match upload_service
            .upload_model(&model_dir, &model_name, args.force)
            .await
        {
            Ok(()) => {
                self.ui.blank_line();
                self.ui.status("Upload", "Success", true);
                self.ui.success(&format!(
                    "Encrypted model '{}' uploaded successfully!",
                    model_name
                ));
                self.ui
                    .info("Model is now available on the KoalaVault platform");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::utils::test_helpers::{create_mock_safetensors_file, create_temp_dir};
    use std::fs::File;

    #[test]
    fn test_extract_metadata_from_header_too_short() {
        let content = vec![0u8; 4];
        let result = extract_metadata_from_header(&content);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Also test header len check
        let content = 100u64.to_le_bytes().to_vec();
        // length says 100, but we provide 0 more
        let result = extract_metadata_from_header(&content);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_extract_metadata_no_metadata_field() {
        let json = r#"{"other": "field"}"#;
        let json_bytes = json.as_bytes();
        let len = json_bytes.len() as u64;

        let mut content = len.to_le_bytes().to_vec();
        content.extend_from_slice(json_bytes);

        let result = extract_metadata_from_header(&content).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_metadata_with_reserved_fields() {
        let json = r#"{"__metadata__": {"__reserved": "val", "user": "data", "test": "123"}}"#;
        let json_bytes = json.as_bytes();
        let len = json_bytes.len() as u64;

        let mut content = len.to_le_bytes().to_vec();
        content.extend_from_slice(json_bytes);

        let result = extract_metadata_from_header(&content).unwrap().unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("user").unwrap(), "data");
        assert_eq!(result.get("test").unwrap(), "123");
        assert!(!result.contains_key("__reserved"));
    }

    #[tokio::test]
    async fn test_model_directory_not_exists() {
        let path = Path::new("/non/existent/path/12345");
        let result = ModelDirectory::from_path(path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_model_directory_empty() {
        let temp_dir = create_temp_dir();
        let result = ModelDirectory::from_path(temp_dir.path()).await;
        assert!(result.is_err()); // Should fail with "No safetensors or cryptotensors files found"
    }

    #[tokio::test]
    async fn test_model_directory_scan() {
        let temp_dir = create_temp_dir();

        // Create a regular file (ignored)
        let _ = File::create(temp_dir.path().join("readme.md")).unwrap();

        // Create a unencrypted safetensors file
        let _ = create_mock_safetensors_file(&temp_dir, "model-01.safetensors", false);

        // Create an encrypted safetensors file
        let _ = create_mock_safetensors_file(&temp_dir, "model-02.safetensors", true);

        let dir = ModelDirectory::from_path(temp_dir.path()).await.unwrap();

        assert_eq!(dir.all_files.len(), 2);

        assert!(!dir.is_fully_encrypted());
        assert_eq!(dir.unencrypted_files.len(), 1);
        assert_eq!(dir.unencrypted_files[0].name, "model-01.safetensors");

        assert_eq!(dir.encrypted_files.len(), 1);
        assert_eq!(dir.encrypted_files[0].name, "model-02.safetensors");
    }

    #[tokio::test]
    async fn test_model_directory_fully_encrypted() {
        let temp_dir = create_temp_dir();
        create_mock_safetensors_file(&temp_dir, "model-01.safetensors", true);
        create_mock_safetensors_file(&temp_dir, "model-02.safetensors", true);

        let dir = ModelDirectory::from_path(temp_dir.path()).await.unwrap();

        assert!(dir.is_fully_encrypted());
        assert_eq!(dir.all_files.len(), 2);
        assert_eq!(dir.unencrypted_files.len(), 0);
        assert_eq!(dir.encrypted_files.len(), 2);
    }

    #[tokio::test]
    async fn test_model_file_from_path() {
        let temp_dir = create_temp_dir();
        let path = create_mock_safetensors_file(&temp_dir, "test.safetensors", false);

        let model_file = ModelFile::from_path(&path).await.unwrap();
        assert_eq!(model_file.name, "test.safetensors");
        assert!(!model_file.is_encrypted);

        let path_enc = create_mock_safetensors_file(&temp_dir, "test_enc.safetensors", true);
        let model_file_enc = ModelFile::from_path(&path_enc).await.unwrap();
        assert_eq!(model_file_enc.name, "test_enc.safetensors");
        assert!(model_file_enc.is_encrypted);
    }
}

//! Upload service for koava

use std::sync::Arc;

use crate::error::{ConverterError, Result};
use crate::utils::{CryptoUtils, FileInfo};
use crate::client::HttpClient;
use crate::model::ModelDirectory;
use crate::file::ModelFileService;
use crate::ui::{create_progress_bar, UI};

pub struct UploadService {
    client: Arc<HttpClient>,
    show_progress: bool,
    ui: UI,
}

impl UploadService {
    pub fn new(client: Arc<HttpClient>, show_progress: bool) -> Self {
        Self {
            client,
            show_progress,
            ui: UI::new(),
        }
    }

    /// Upload a model to the server
    pub async fn upload_model(
        &self,
        model_dir: &ModelDirectory,
        model_name: &str,
        force: bool,
    ) -> Result<()> {
        let encrypted_files = model_dir.get_encrypted_files();

        if encrypted_files.is_empty() {
            return Err(ConverterError::validation("No encrypted files to upload"));
        }

        // Get username
        let username = self
            .client
            .get_current_username()
            .ok_or_else(|| ConverterError::Authentication("Failed to get username".to_string()))?;

        // Extract headers from each file
        let mut file_infos = Vec::new();

        let pb = if self.show_progress {
            Some(create_progress_bar(
                encrypted_files.len() as u64,
                "Extracting headers...",
            ))
        } else {
            None
        };

        for file in encrypted_files {
            if let Some(pb) = &pb {
                pb.set_message(format!("Processing {}", file.name));
            }

            // Extract header
            let header_b64 = CryptoUtils::extract_safetensors_header(&file.path)
                .map_err(|e| ConverterError::File(format!("Failed to extract header: {}", e)))?;

            file_infos.push(FileInfo {
                id: None,
                filename: file.name.clone(),
                file_header: Some(header_b64),
                created_at: None,
                updated_at: None,
            });

            if let Some(pb) = &pb {
                pb.inc(1);
            }
        }

        if let Some(pb) = &pb {
            pb.finish_with_message("Headers extracted");
        }

        // Upload to server
        let file_service = ModelFileService::new(&self.client);

        self.ui.info(&format!(
            "Uploading {} files to {}/{}...",
            file_infos.len(),
            username,
            model_name
        ));

        match file_service
            .upload_model_files(&username, model_name, file_infos)
            .await
        {
            Ok(response) => {
                self.ui.success(&format!(
                    "Uploaded {} files",
                    response.total_uploaded
                ));
                Ok(())
            }
            Err(e) => {
                self.ui.error(&format!("Upload failed: {}", e));
                Err(ConverterError::Upload(format!("Upload failed: {}", e)))
            }
        }
    }
}


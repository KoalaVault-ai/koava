//! Push service for publishing models to KoalaVault and Hugging Face

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{KoavaError, Result};
use crate::ui::UI;
use crate::{CreateArgs, EncryptArgs, PushArgs};

/// Push service for CLI commands
pub struct PushService {
    config: Config,
    ui: UI,
}

impl PushService {
    /// Create a new push service
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ui: UI::new(),
        }
    }

    /// Push model: create -> encrypt -> upload -> hf create repo -> upload to hf -> update model
    pub async fn push<C: crate::client::ApiClient + ?Sized>(
        &mut self,
        client: Arc<C>,
        args: PushArgs,
    ) -> Result<()> {
        // Check Hugging Face CLI login status first
        self.ui.info("Checking Hugging Face CLI login status...");
        let hf_status = crate::huggingface::check_huggingface_cli_status(&self.config).await?;
        match hf_status {
            crate::huggingface::HuggingFaceCliStatus::NotFound => {
                return Err(KoavaError::config(
                    "Hugging Face CLI not found. Please install it first.".to_string(),
                ));
            }
            crate::huggingface::HuggingFaceCliStatus::NotLoggedIn => {
                return Err(KoavaError::config(
                    "Not logged in to Hugging Face. Please run 'hf auth login' first.".to_string(),
                ));
            }
            crate::huggingface::HuggingFaceCliStatus::LoggedIn(username) => {
                self.ui
                    .success(&format!("Hugging Face CLI: Logged in as {}", username));
            }
        }

        // 1) Create model on server
        // Infer model name from path, handling "." case by canonicalizing
        let model_name = if let Some(name) = &args.name {
            name.clone()
        } else {
            use std::path::{Component, Path};

            let basename_from = |p: &Path| -> Option<String> {
                p.components().rev().find_map(|c| match c {
                    Component::Normal(s) => s.to_str().map(|s| s.to_string()),
                    _ => None,
                })
            };

            // Canonicalize path to handle "." case
            match args.model_path.canonicalize() {
                Ok(canonical_path) => basename_from(canonical_path.as_path())
                    .unwrap_or_else(|| "unknown-model".to_string()),
                Err(_) => {
                    // Fallback to file_name if canonicalize fails
                    args.model_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown-model".to_string())
                }
            }
        };

        // Display header for publish flow
        self.ui.header("Publishing Model");
        self.ui.info(&format!("Model: {}", model_name));
        self.ui
            .info(&format!("Path: {}", args.model_path.display()));
        self.ui.separator();

        // Step 1: Create model on server
        self.ui
            .info(&format!("Step 1/6: Creating model '{}'...", model_name));
        let model_service = crate::model::ModelService::new();
        model_service
            .create(
                client.clone(),
                CreateArgs {
                    name: model_name.clone(),
                    description: args.description.clone(),
                },
            )
            .await?;
        self.ui.separator();

        // Step 2: Encrypt local files
        self.ui.info(&format!(
            "Step 2/6: Encrypting files at '{}'...",
            args.model_path.display()
        ));
        let encrypt_service = crate::encrypt::EncryptService::new(self.config.clone());
        encrypt_service
            .encrypt(
                &*client,
                EncryptArgs {
                    model_path: args.model_path.clone(),
                    name: Some(model_name.clone()),
                    output: None,
                    no_backup: false,
                    files: None,
                    exclude: None,
                    dry_run: false,
                    force: args.force,
                },
            )
            .await?;
        self.ui.separator();

        // Step 3: Upload to server
        self.ui
            .info("Step 3/6: Uploading encrypted files to server...");
        // Note: handle_upload logic will be moved to UploadService later
        // For now, we'll call it through a helper method
        self.upload_to_server(client.clone(), &args.model_path, &model_name, args.force)
            .await?;
        self.ui.separator();

        // Step 4: Create Hugging Face repository
        self.ui
            .info("Step 4/6: Creating Hugging Face repository...");
        let hf_repo_name = self.create_hf_repository(&model_name, args.public).await?;
        self.ui.separator();

        // Step 5: Upload to Hugging Face
        self.ui.info("Step 5/6: Uploading to Hugging Face...");
        self.upload_to_hf(&args.model_path, &hf_repo_name).await?;
        self.ui.separator();

        // Step 6: Update model with HF URL and README
        self.ui
            .info("Step 6/6: Updating model with Hugging Face information...");
        self.update_model_with_hf_info(
            client,
            &model_name,
            &hf_repo_name,
            &args.description,
            &args.model_path,
        )
        .await?;

        self.ui.blank_line();
        self.ui.status("Publish", "Success", true);
        self.ui.success("Publish completed successfully.");
        Ok(())
    }

    /// Upload model to server (temporary helper until UploadService is enhanced)
    async fn upload_to_server<C: crate::client::ApiClient + ?Sized>(
        &self,
        client: Arc<C>,
        model_path: &Path,
        model_name: &str,
        force: bool,
    ) -> Result<()> {
        // This is a temporary implementation
        // TODO: Move this logic to UploadService
        let upload_service = crate::upload::UploadService::new(client, true);
        let model_dir = crate::ModelDirectory::from_path(model_path).await?;

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

        upload_service
            .upload_model(&model_dir, model_name, force)
            .await
    }

    /// Create Hugging Face repository
    async fn create_hf_repository(&self, model_name: &str, public: bool) -> Result<String> {
        let hf_cli_path = match &self.config.huggingface_cli_path {
            Some(path) => path.clone(),
            None => {
                return Err(KoavaError::config("Hugging Face CLI not configured. Please run 'koava config set-huggingface-cli auto' first.".to_string()));
            }
        };

        // Check if user is logged in to Hugging Face
        let status = crate::huggingface::check_huggingface_cli_status(&self.config).await?;
        let username = match status {
            crate::huggingface::HuggingFaceCliStatus::LoggedIn(user) => user,
            _ => {
                return Err(KoavaError::config(
                    "Not logged in to Hugging Face. Please run 'hf auth login' first.".to_string(),
                ));
            }
        };

        let repo_name = format!("{}/{}", username, model_name);

        // Create repository using hf CLI
        let mut cmd = tokio::process::Command::new(&hf_cli_path);
        cmd.arg("repo")
            .arg("create")
            .arg(&repo_name)
            .arg("--repo-type")
            .arg("model");

        // Add privacy setting
        if !public {
            cmd.arg("--private");
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| KoavaError::config(format!("Failed to create HF repository: {}", e)))?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("already exists") {
                self.ui.info(&format!(
                    "Repository {} already exists, using existing repository",
                    repo_name
                ));
            } else {
                return Err(KoavaError::config(format!(
                    "Failed to create HF repository: {}",
                    error_msg
                )));
            }
        } else {
            let privacy_status = if public { "public" } else { "private" };
            self.ui.success(&format!(
                "Created Hugging Face repository: https://huggingface.co/{}",
                repo_name
            ));
            self.ui.info(&format!(
                "Repository created as {}. You can manually publish it on Hugging Face if needed.",
                privacy_status
            ));
        }

        Ok(repo_name)
    }

    /// Upload model files to Hugging Face
    async fn upload_to_hf(&self, model_path: &Path, repo_name: &str) -> Result<()> {
        let hf_cli_path = match &self.config.huggingface_cli_path {
            Some(path) => path.clone(),
            None => {
                return Err(KoavaError::config(
                    "Hugging Face CLI not configured".to_string(),
                ));
            }
        };

        // Upload using huggingface-cli (single call), excluding the top-level .backup directory precisely
        // Patterns are evaluated relative to local_path (model_path)
        let status = tokio::process::Command::new(&hf_cli_path)
            .arg("upload")
            .arg(repo_name)
            .arg(model_path)
            .arg("--repo-type")
            .arg("model")
            .arg("--exclude")
            .arg(".backup")
            .arg("--exclude")
            .arg(".backup/**")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|e| KoavaError::config(format!("Failed to upload to HF: {}", e)))?;

        if !status.success() {
            return Err(KoavaError::config(
                "Failed to upload to HF (non-zero exit)".to_string(),
            ));
        }

        self.ui.success(&format!(
            "Uploaded model to Hugging Face: https://huggingface.co/{}",
            repo_name
        ));
        Ok(())
    }

    /// Update KoalaVault model with Hugging Face information
    async fn update_model_with_hf_info<C: crate::client::ApiClient + ?Sized>(
        &self,
        client: Arc<C>,
        model_name: &str,
        hf_repo_name: &str,
        description: &Option<String>,
        model_path: &Path,
    ) -> Result<()> {
        let username = client.get_current_username().ok_or_else(|| {
            KoavaError::authentication("Could not get current username".to_string())
        })?;

        // Try to read existing README file, or create a default one
        let readme_content =
            self.read_or_create_readme(model_path, model_name, hf_repo_name, description)?;

        // Update model with HF URL and README
        let update_data = serde_json::json!({
            "repository_url": format!("https://huggingface.co/{}", hf_repo_name),
            "readme_content": readme_content,
            "description": description.as_deref().unwrap_or("")
        });

        let endpoint = format!("resources/{}/models/{}", username, model_name);
        let response: crate::ApiResponse<serde_json::Value> = client
            .authenticated_request(reqwest::Method::PUT, &endpoint, Some(&update_data))
            .await?;

        if response.success {
            self.ui
                .success("Updated model with Hugging Face information");
        } else {
            self.ui
                .warning("Model created but failed to update with HF information");
        }

        Ok(())
    }

    /// Read existing README file or create a default one
    fn read_or_create_readme(
        &self,
        model_path: &Path,
        model_name: &str,
        hf_repo_name: &str,
        description: &Option<String>,
    ) -> Result<String> {
        // Try to find README file in the model directory
        let readme_candidates = vec![
            model_path.join("README.md"),
            model_path.join("readme.md"),
            model_path.join("README.txt"),
            model_path.join("readme.txt"),
        ];

        for readme_path in readme_candidates {
            if readme_path.exists() {
                match std::fs::read_to_string(&readme_path) {
                    Ok(content) => {
                        self.ui.info(&format!(
                            "Using existing README file: {}",
                            readme_path.display()
                        ));
                        return Ok(content);
                    }
                    Err(e) => {
                        self.ui.warning(&format!(
                            "Failed to read README file {}: {}",
                            readme_path.display(),
                            e
                        ));
                        continue;
                    }
                }
            }
        }

        // No README file found, create a default one
        self.ui
            .info("No README file found, creating default README");
        let default_readme = format!(
            "# {}\n\n{}\n\n## Hugging Face\n\nThis model is also available on Hugging Face: https://huggingface.co/{}\n\n## Usage\n\nThis model is encrypted and requires KoalaVault for decryption and usage.",
            model_name,
            description.as_deref().unwrap_or("A model published via KoalaVault"),
            hf_repo_name
        );

        Ok(default_readme)
    }
}

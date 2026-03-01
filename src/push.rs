//! Push service for publishing models to KoalaVault and Hugging Face

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;

use crate::client::ApiClient;
use crate::config::Config;
use crate::error::{KoavaError, Result};
use crate::huggingface::HuggingFaceCliStatus;
use crate::ui::UI;
use crate::{CreateArgs, EncryptArgs, PushArgs};

/// Function alias for object-safe async trait methods
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Operations trait to abstract external dependencies for PushService
pub trait PushOperations<C: ApiClient + 'static + ?Sized>: Send + Sync {
    /// Check Hugging Face CLI login status
    fn check_hf_status<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<HuggingFaceCliStatus>>;

    /// Create model on KoalaVault server
    fn create_model<'a>(&'a self, client: Arc<C>, args: CreateArgs) -> BoxFuture<'a, Result<()>>;

    /// Encrypt local model files
    fn encrypt_model<'a>(
        &'a self,
        client: &'a C,
        config: Config,
        args: EncryptArgs,
    ) -> BoxFuture<'a, Result<()>>;

    /// Upload encrypted model to KoalaVault server
    fn upload_to_server<'a>(
        &'a self,
        client: Arc<C>,
        model_path: PathBuf,
        model_name: String,
        force: bool,
    ) -> BoxFuture<'a, Result<()>>;

    /// Create Hugging Face repository
    fn create_hf_repository<'a>(
        &'a self,
        config: &'a Config,
        model_name: String,
        public: bool,
    ) -> BoxFuture<'a, Result<String>>;

    /// Upload model to Hugging Face
    fn upload_to_hf<'a>(
        &'a self,
        config: &'a Config,
        model_path: PathBuf,
        repo_name: String,
    ) -> BoxFuture<'a, Result<()>>;

    /// Update model with Hugging Face information
    fn update_model_with_hf_info<'a>(
        &'a self,
        client: Arc<C>,
        model_name: String,
        hf_repo_name: String,
        description: Option<String>,
        model_path: PathBuf,
    ) -> BoxFuture<'a, Result<()>>;

    /// Resolve the model name from arguments or path
    fn resolve_model_name(&self, args: &PushArgs) -> String;
}

/// Push service for CLI commands
pub struct PushService<C: ApiClient + 'static + ?Sized> {
    config: Config,
    ui: UI,
    // We use a boxed trait object to allow swapping implementations (e.g. for testing)
    // The trait is generic over C because ApiClient is not object-safe
    ops: Box<dyn PushOperations<C>>,
}

impl<C: ApiClient + 'static> PushService<C> {
    /// Create a new push service with default operations
    pub fn new(config: Config) -> Self {
        Self {
            config: config.clone(),
            ui: UI::new(),
            ops: Box::new(RealPushOperations::new()),
        }
    }

    /// Create a new push service with custom operations
    #[allow(dead_code)]
    pub fn new_with_ops(config: Config, ops: Box<dyn PushOperations<C>>) -> Self {
        Self {
            config,
            ui: UI::new(),
            ops,
        }
    }

    /// Push model: create -> encrypt -> upload -> hf create repo -> upload to hf -> update model
    pub async fn push(&mut self, client: Arc<C>, args: PushArgs) -> Result<()> {
        // Check Hugging Face CLI login status first
        self.ui.info("Checking Hugging Face CLI login status...");
        let hf_status = self.ops.check_hf_status(&self.config).await?;

        match hf_status {
            HuggingFaceCliStatus::NotFound => {
                return Err(KoavaError::config(
                    "Hugging Face CLI not found. Please install it first.".to_string(),
                ));
            }
            HuggingFaceCliStatus::NotLoggedIn => {
                return Err(KoavaError::config(
                    "Not logged in to Hugging Face. Please run 'hf auth login' first.".to_string(),
                ));
            }
            HuggingFaceCliStatus::LoggedIn(username) => {
                self.ui
                    .success(&format!("Hugging Face CLI: Logged in as {}", username));
            }
        }

        // Infer model name
        let model_name = self.ops.resolve_model_name(&args);

        // Display header for publish flow
        self.ui.header("Publishing Model");
        self.ui.info(&format!("Model: {}", model_name));
        self.ui
            .info(&format!("Path: {}", args.model_path.display()));
        self.ui.separator();

        // Step 1: Create model on server
        self.ui
            .info(&format!("Step 1/6: Creating model '{}'...", model_name));

        self.ops
            .create_model(
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

        self.ops
            .encrypt_model(
                &*client,
                self.config.clone(),
                EncryptArgs {
                    model_path: args.model_path.clone(),
                    name: Some(model_name.clone()),
                    output: None,
                    no_backup: false,
                    files: None,
                    exclude: None,
                    dry_run: false,
                    force: args.force,
                    master_key: None,
                    sign_key: None,
                },
            )
            .await?;

        self.ui.separator();

        // Step 3: Upload to server
        self.ui
            .info("Step 3/6: Uploading encrypted files to server...");

        self.ops
            .upload_to_server(
                client.clone(),
                args.model_path.clone(),
                model_name.clone(),
                args.force,
            )
            .await?;

        self.ui.separator();

        // Step 4: Create Hugging Face repository
        self.ui
            .info("Step 4/6: Creating Hugging Face repository...");
        let hf_repo_name = self
            .ops
            .create_hf_repository(&self.config, model_name.clone(), args.public)
            .await?;
        self.ui.separator();

        // Step 5: Upload to Hugging Face
        self.ui.info("Step 5/6: Uploading to Hugging Face...");
        self.ops
            .upload_to_hf(&self.config, args.model_path.clone(), hf_repo_name.clone())
            .await?;
        self.ui.separator();

        // Step 6: Update model with HF URL and README
        self.ui
            .info("Step 6/6: Updating model with Hugging Face information...");
        self.ops
            .update_model_with_hf_info(
                client,
                model_name,
                hf_repo_name,
                args.description,
                args.model_path,
            )
            .await?;

        self.ui.blank_line();
        self.ui.status("Publish", "Success", true);
        self.ui.success("Publish completed successfully.");
        Ok(())
    }
}

/// Real implementation of PushOperations
pub struct RealPushOperations {
    ui: UI,
}

impl RealPushOperations {
    pub fn new() -> Self {
        Self { ui: UI::new() }
    }

    /// Read existing README file or create a default one
    async fn read_or_create_readme(
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
            if tokio::fs::try_exists(&readme_path).await.unwrap_or(false) {
                match tokio::fs::read_to_string(&readme_path).await {
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

impl<C: ApiClient + 'static + ?Sized> PushOperations<C> for RealPushOperations {
    fn check_hf_status<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<HuggingFaceCliStatus>> {
        let config = config.clone();
        Box::pin(async move { crate::huggingface::check_huggingface_cli_status(&config).await })
    }

    fn create_model<'a>(&'a self, client: Arc<C>, args: CreateArgs) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let model_service = crate::model::ModelService::new();
            model_service.create(client, args).await
        })
    }

    fn encrypt_model<'a>(
        &'a self,
        client: &'a C,
        config: Config,
        args: EncryptArgs,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let encrypt_service = crate::encrypt::EncryptService::new(config);
            encrypt_service.encrypt(client, args).await
        })
    }

    fn upload_to_server<'a>(
        &'a self,
        client: Arc<C>,
        model_path: PathBuf,
        model_name: String,
        force: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let upload_service = crate::upload::UploadService::new(client, true);
            let model_dir = crate::ModelDirectory::from_path(&model_path).await?;

            if !model_dir.is_fully_encrypted() {
                return Err(KoavaError::validation(
                    "Model is not fully encrypted. Please encrypt first using 'koava encrypt'.",
                ));
            }

            upload_service
                .upload_model(&model_dir, &model_name, force)
                .await
        })
    }

    fn create_hf_repository<'a>(
        &'a self,
        config: &'a Config,
        model_name: String,
        public: bool,
    ) -> BoxFuture<'a, Result<String>> {
        let config = config.clone();
        Box::pin(async move {
            let hf_cli_path = match &config.huggingface_cli_path {
                Some(path) => path.clone(),
                None => {
                    return Err(KoavaError::config("Hugging Face CLI not configured. Please run 'koava config set-huggingface-cli auto' first.".to_string()));
                }
            };

            // Check if user is logged in to Hugging Face
            let status = crate::huggingface::check_huggingface_cli_status(&config).await?;
            let username = match status {
                HuggingFaceCliStatus::LoggedIn(user) => user,
                _ => {
                    return Err(KoavaError::config(
                        "Not logged in to Hugging Face. Please run 'hf auth login' first."
                            .to_string(),
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

            if !public {
                cmd.arg("--private");
            }

            let output = cmd.output().await.map_err(|e| {
                KoavaError::config(format!("Failed to create HF repository: {}", e))
            })?;

            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                if !error_msg.contains("already exists") {
                    return Err(KoavaError::config(format!(
                        "Failed to create HF repository: {}",
                        error_msg
                    )));
                }
            }
            Ok(repo_name)
        })
    }

    fn upload_to_hf<'a>(
        &'a self,
        config: &'a Config,
        model_path: PathBuf,
        repo_name: String,
    ) -> BoxFuture<'a, Result<()>> {
        let config = config.clone();
        Box::pin(async move {
            let hf_cli_path = match &config.huggingface_cli_path {
                Some(path) => path.clone(),
                None => {
                    return Err(KoavaError::config(
                        "Hugging Face CLI not configured".to_string(),
                    ));
                }
            };

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

            Ok(())
        })
    }

    fn update_model_with_hf_info<'a>(
        &'a self,
        client: Arc<C>,
        model_name: String,
        hf_repo_name: String,
        description: Option<String>,
        model_path: PathBuf,
    ) -> BoxFuture<'a, Result<()>> {
        let description_clone = description.clone();
        Box::pin(async move {
            let username = client.get_current_username().ok_or_else(|| {
                KoavaError::authentication("Could not get current username".to_string())
            })?;

            let readme_content = self
                .read_or_create_readme(&model_path, &model_name, &hf_repo_name, &description_clone)
                .await?;

            let update_data = serde_json::json!({
                "repository_url": format!("https://huggingface.co/{}", hf_repo_name),
                "readme_content": readme_content,
                "description": description_clone.as_deref().unwrap_or("")
            });

            let endpoint = format!("resources/{}/models/{}", username, model_name);
            let response: crate::ApiResponse<serde_json::Value> = client
                .authenticated_request(reqwest::Method::PUT, &endpoint, Some(&update_data))
                .await?;

            if response.success {
                self.ui
                    .success("Updated model with Hugging Face information");
            }

            Ok(())
        })
    }

    fn resolve_model_name(&self, args: &PushArgs) -> String {
        if let Some(name) = &args.name {
            name.clone()
        } else {
            crate::utils::infer_model_name_from_path(&args.model_path)
                .unwrap_or_else(|| "unknown-model".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mocks::MockApiClient;
    use std::sync::Mutex;

    // Manual Mock for PushOperations
    struct MockPushOperations {
        check_hf_status_result: Mutex<Option<Result<HuggingFaceCliStatus>>>,
        create_model_result: Mutex<Option<Result<()>>>,
        encrypt_model_result: Mutex<Option<Result<()>>>,
        upload_to_server_result: Mutex<Option<Result<()>>>,
        create_hf_repository_result: Mutex<Option<Result<String>>>,
        upload_to_hf_result: Mutex<Option<Result<()>>>,
        update_model_with_hf_info_result: Mutex<Option<Result<()>>>,
        resolve_model_name_result: String,
    }

    impl MockPushOperations {
        fn new() -> Self {
            Self {
                check_hf_status_result: Mutex::new(Some(Ok(HuggingFaceCliStatus::LoggedIn(
                    "user".to_string(),
                )))),
                create_model_result: Mutex::new(Some(Ok(()))),
                encrypt_model_result: Mutex::new(Some(Ok(()))),
                upload_to_server_result: Mutex::new(Some(Ok(()))),
                create_hf_repository_result: Mutex::new(Some(Ok("user/model".to_string()))),
                upload_to_hf_result: Mutex::new(Some(Ok(()))),
                update_model_with_hf_info_result: Mutex::new(Some(Ok(()))),
                resolve_model_name_result: "test_model".to_string(),
            }
        }

        fn with_hf_status(self, status: HuggingFaceCliStatus) -> Self {
            *self.check_hf_status_result.lock().unwrap() = Some(Ok(status));
            self
        }

        fn with_create_model_error(self) -> Self {
            *self.create_model_result.lock().unwrap() =
                Some(Err(KoavaError::api(500, "Server error".to_string())));
            self
        }
    }

    impl<C: ApiClient + 'static + ?Sized> PushOperations<C> for MockPushOperations {
        fn check_hf_status<'a>(
            &'a self,
            _config: &'a Config,
        ) -> BoxFuture<'a, Result<HuggingFaceCliStatus>> {
            let result = self
                .check_hf_status_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn create_model<'a>(
            &'a self,
            _client: Arc<C>,
            _args: CreateArgs,
        ) -> BoxFuture<'a, Result<()>> {
            let result = self
                .create_model_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn encrypt_model<'a>(
            &'a self,
            _client: &'a C,
            _config: Config,
            _args: EncryptArgs,
        ) -> BoxFuture<'a, Result<()>> {
            let result = self
                .encrypt_model_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn upload_to_server<'a>(
            &'a self,
            _client: Arc<C>,
            _model_path: PathBuf,
            _model_name: String,
            _force: bool,
        ) -> BoxFuture<'a, Result<()>> {
            let result = self
                .upload_to_server_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn create_hf_repository<'a>(
            &'a self,
            _config: &'a Config,
            _model_name: String,
            _public: bool,
        ) -> BoxFuture<'a, Result<String>> {
            let result = self
                .create_hf_repository_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn upload_to_hf<'a>(
            &'a self,
            _config: &'a Config,
            _model_path: PathBuf,
            _repo_name: String,
        ) -> BoxFuture<'a, Result<()>> {
            let result = self
                .upload_to_hf_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn update_model_with_hf_info<'a>(
            &'a self,
            _client: Arc<C>,
            _model_name: String,
            _hf_repo_name: String,
            _description: Option<String>,
            _model_path: PathBuf,
        ) -> BoxFuture<'a, Result<()>> {
            let result = self
                .update_model_with_hf_info_result
                .lock()
                .unwrap()
                .take()
                .expect("Mock result already consumed");
            Box::pin(async move { result })
        }

        fn resolve_model_name(&self, _args: &PushArgs) -> String {
            self.resolve_model_name_result.clone()
        }
    }

    #[tokio::test]
    async fn test_push_workflow_success() {
        let config = Config::default();
        let mock_ops = MockPushOperations::new();
        // Use shared mock client
        let client = Arc::new(MockApiClient::new(config.clone()).with_auth("testuser".to_string()));

        let args = PushArgs {
            model_path: PathBuf::from("test"),
            name: Some("test".to_string()),
            description: None,
            force: false,
            public: false,
        };

        let mut push_service = PushService::new_with_ops(config, Box::new(mock_ops));
        let result = push_service.push(client, args).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_push_hf_not_logged_in() {
        let config = Config::default();
        let mock_ops = MockPushOperations::new().with_hf_status(HuggingFaceCliStatus::NotLoggedIn);
        let client = Arc::new(MockApiClient::new(config.clone()).with_auth("testuser".to_string()));

        let args = PushArgs {
            model_path: PathBuf::from("test"),
            name: Some("test".to_string()),
            description: None,
            force: false,
            public: false,
        };

        let mut push_service = PushService::new_with_ops(config, Box::new(mock_ops));
        let result = push_service.push(client, args).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not logged in"));
    }

    #[tokio::test]
    async fn test_push_create_model_fail() {
        let config = Config::default();
        let mock_ops = MockPushOperations::new().with_create_model_error();
        let client = Arc::new(MockApiClient::new(config.clone()).with_auth("testuser".to_string()));

        let args = PushArgs {
            model_path: PathBuf::from("test"),
            name: Some("test".to_string()),
            description: None,
            force: false,
            public: false,
        };

        let mut push_service = PushService::new_with_ops(config, Box::new(mock_ops));
        let result = push_service.push(client, args).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Server error"));
    }
}

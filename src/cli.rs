//! CLI handler for koava

use dialoguer::{theme::ColorfulTheme, Confirm};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use crate::config::ConverterConfig;
use crate::encrypt::EncryptService;
use crate::error::{ConverterError, Result};
use crate::client::HttpClient;
use crate::model::ModelDirectory;
use crate::file::ModelFileService;
use crate::client::ApiResponse;
use crate::ui::UI;
use crate::upload::UploadService;
use crate::version::CURRENT_VERSION;
use crate::{
    Commands, ConfigCommand, CreateArgs, EncryptArgs, ListArgs, LoginArgs, PushArgs, RemoveArgs,
    RestoreArgs, UploadArgs,
};

pub struct CliHandler {
    config: ConverterConfig,
    client: Option<Arc<HttpClient>>,
    ui: UI,
}

impl CliHandler {
    pub async fn new(config_path: Option<&Path>) -> Result<Self> {
        let config = ConverterConfig::load(config_path).await?;

        Ok(Self {
            config,
            client: None,
            ui: UI::new(),
        })
    }

    pub async fn execute(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Encrypt(args) => self.handle_encrypt(args).await,
            Commands::Upload(args) => self.handle_upload(args).await,
            Commands::Restore(args) => self.handle_restore(args).await,
            Commands::Remove(args) => self.handle_remove(args).await,
            Commands::Status => self.handle_status().await,
            Commands::Config(args) => self.handle_config(args).await,
            Commands::Login(args) => self.handle_login(args).await,
            Commands::Logout => self.handle_logout().await,
            Commands::List(args) => self.handle_list(args).await,
            Commands::Create(args) => self.handle_create(args).await,
            Commands::Push(args) => self.handle_push(args).await,
        }
    }

    async fn handle_encrypt(&mut self, args: EncryptArgs) -> Result<()> {
        let encrypt_service = EncryptService::new(self.config.clone());
        encrypt_service.encrypt(args).await
    }

    async fn handle_restore(&mut self, args: RestoreArgs) -> Result<()> {
        let encrypt_service = EncryptService::new(self.config.clone());
        encrypt_service.restore(args).await
    }

    async fn handle_upload(&mut self, args: UploadArgs) -> Result<()> {
        let client = self.get_authenticated_client().await?;

        self.ui
            .info(&format!("Scanning: {}", args.model_path.display()));

        let model_dir = ModelDirectory::from_path(&args.model_path).await?;

        if !model_dir.is_fully_encrypted() {
            let unencrypted_files = model_dir.get_unencrypted_files();
            self.ui.error("Model contains unencrypted files:");
            for file in unencrypted_files {
                self.ui.error(&format!("  - {}", file.name));
            }
            self.ui.info("Please encrypt first using: koava encrypt <MODEL_PATH>");
            return Err(ConverterError::validation("Model is not fully encrypted"));
        }

        let model_name = if let Some(name) = &args.name {
            name.clone()
        } else {
            get_model_name_from_path(&model_dir.path)?
        };

        let username = client
            .get_current_username()
            .ok_or_else(|| ConverterError::Authentication("Failed to get username".to_string()))?;

        self.ui.info(&format!("Model: {}/{}", username, model_name));
        self.ui.info(&format!("Size: {}", model_dir.formatted_size()));
        self.ui.info(&format!("Files: {}", model_dir.get_encrypted_files().len()));

        let upload_service = UploadService::new(client, true);

        self.ui.info("Uploading...");
        match upload_service
            .upload_model(&model_dir, &model_name, args.force)
            .await
        {
            Ok(()) => {
                self.ui.success(&format!("Model '{}' uploaded!", model_name));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn handle_remove(&mut self, args: RemoveArgs) -> Result<()> {
        let client = self.get_authenticated_client().await?;

        let (username, model_name) = parse_model_identifier(&args.model_identifier, &client)?;

        if !args.force {
            let should_remove = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(&format!(
                    "Remove all files for '{}/{}'?",
                    username, model_name
                ))
                .default(false)
                .interact()
                .map_err(|_| ConverterError::InvalidInput("Failed to read confirmation".to_string()))?;

            if !should_remove {
                self.ui.info("Cancelled.");
                return Ok(());
            }
        }

        let file_service = ModelFileService::new(&client);

        match file_service
            .delete_all_model_files(&username, &model_name)
            .await
        {
            Ok(_) => {
                self.ui.blank_line();
                self.ui
                    .success(&format!("Removed files for {}/{}", username, model_name));
                Ok(())
            }
            Err(e) => {
                self.ui.blank_line();
                self.ui.error(&format!("Failed to remove: {}", e));
                Err(ConverterError::Upload(format!("Remove failed: {}", e)))
            }
        }
    }

    async fn handle_status(&mut self) -> Result<()> {
        let mut username_opt: Option<String> = None;
        let mut authenticated = false;

        if let Ok(client) = HttpClient::new(self.config.to_sdk_config()) {
            if client.is_authenticated() {
                username_opt = client.get_current_username();
                authenticated = username_opt.is_some();
            }
        }

        let (server_connected, server_status_msg) = match self.check_server_health().await {
            Ok(_) => (true, "Connected".to_string()),
            Err(e) => (false, format!("{}", e)),
        };

        let hf_status = self.config.check_huggingface_cli_status().await?;
        let hf_status_str = self.ui.format_huggingface_cli_status(&hf_status);

        let status_info = vec![
            ("Version", CURRENT_VERSION.to_string()),
            (
                "Authentication",
                self.ui.format_auth_status(authenticated, false),
            ),
            ("Username", self.ui.format_user_field(username_opt)),
            (
                "Server",
                if server_connected {
                    self.ui.format_server_status(true)
                } else {
                    format!("{} ({})", self.ui.format_server_status(false), server_status_msg)
                },
            ),
            ("Hugging Face CLI", hf_status_str),
        ];

        self.ui.card("Status", status_info);
        Ok(())
    }

    async fn handle_login(&mut self, args: LoginArgs) -> Result<()> {
        let api_key = {
            #[cfg(debug_assertions)]
            {
                args.api_key
            }
            #[cfg(not(debug_assertions))]
            {
                if args.api_key.is_some() {
                    self.ui.warning("API key via CLI ignored for security.");
                }

                dialoguer::Password::new()
                    .with_prompt("Enter your KoalaVault API key")
                    .interact()
                    .map_err(|e| ConverterError::InvalidInput(format!("Failed to read: {}", e)))?
            }
        };

        if api_key.is_empty() {
            return Err(ConverterError::InvalidInput(
                "API key cannot be empty".to_string(),
            ));
        }

        self.ui.info("Authenticating...");

        let sdk_config = self.config.to_sdk_config();
        let mut client = HttpClient::new(sdk_config)?;

        let _access_token = client
            .authenticate(api_key)
            .await
            .map_err(|e| ConverterError::Authentication(format!("Auth failed: {}", e)))?;

        let username = client.get_current_username().ok_or_else(|| {
            ConverterError::Authentication("Failed to get username after auth".to_string())
        })?;

        if !client.is_authenticated() {
            return Err(ConverterError::Authentication(
                "Token storage failed".to_string(),
            ));
        }

        self.client = Some(Arc::new(client));

        self.ui.blank_line();
        self.ui.success(&format!("Authenticated as: {}", username));
        self.ui.info("Credentials stored.");
        Ok(())
    }

    async fn handle_logout(&mut self) -> Result<()> {
        let mut performed_logout = false;

        if let Some(client) = &mut self.client {
            if let Err(e) = client.logout().await {
                self.ui.warning(&format!("Server logout failed: {}", e));
            } else {
                performed_logout = true;
            }
        } else {
            if let Ok(temp_client) = HttpClient::new(self.config.to_sdk_config()) {
                if let Err(e) = temp_client.logout().await {
                    self.ui.warning(&format!("Server logout failed: {}", e));
                } else {
                    performed_logout = true;
                }
            }
        }

        self.client = None;
        if performed_logout {
            self.ui.success("Logged out successfully");
        } else {
            self.ui.warning("Local session cleared");
        }
        Ok(())
    }

    async fn handle_list(&mut self, args: ListArgs) -> Result<()> {
        let client = self.get_authenticated_client().await?;

        let (username, model_name) = parse_model_identifier(&args.model_identifier, &client)?;

        let file_service = ModelFileService::new(&client);

        match file_service.list_model_files(&username, &model_name).await {
            Ok(files) => {
                if files.is_empty() {
                    self.ui.info("No files found.");
                    return Ok(());
                }

                self.ui.info(&format!("Found {} files:", files.len()));
                for file in &files {
                    self.ui.info(&format!(
                        "  {} ({})",
                        file.filename,
                        file.created_at.as_deref().unwrap_or("unknown")
                    ));
                }

                self.ui.blank_line();
                self.ui.success(&format!(
                    "Listed {} files for {}/{}",
                    files.len(),
                    username,
                    model_name
                ));
                Ok(())
            }
            Err(e) => {
                self.ui.error(&format!("Failed to list: {}", e));
                Err(ConverterError::Upload(format!("List failed: {}", e)))
            }
        }
    }

    async fn handle_create(&mut self, args: CreateArgs) -> Result<()> {
        self.ui.info("Creating model...");

        let client = self.get_authenticated_client().await?;

        let username = client
            .get_current_username()
            .ok_or_else(|| ConverterError::Authentication("Failed to get username".to_string()))?;

        let mut request_body = serde_json::Map::new();
        request_body.insert("name".to_string(), serde_json::Value::String(args.name.clone()));

        if let Some(description) = args.description {
            request_body.insert(
                "description".to_string(),
                serde_json::Value::String(description),
            );
        }

        let request_json = serde_json::Value::Object(request_body);
        let endpoint = format!("resources/{}/models", username);

        let response: ApiResponse<serde_json::Value> = client
            .authenticated_request(reqwest::Method::POST, &endpoint, Some(&request_json))
            .await
            .map_err(|e| {
                self.ui.error(&format!("Failed to create: {}", e));
                e
            })?;

        if response.data.is_some() {
            self.ui.success(&format!("Model '{}' created!", args.name));
            Ok(())
        } else {
            let error_message = response
                .error
                .or(response.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            self.ui.error(&format!("Failed: {}", error_message));
            Err(ConverterError::Config(error_message))
        }
    }

    async fn handle_push(&mut self, args: PushArgs) -> Result<()> {
        self.ui.info("Checking Hugging Face CLI...");
        let hf_status = self.config.check_huggingface_cli_status().await?;
        match hf_status {
            crate::config::HuggingFaceCliStatus::NotFound => {
                return Err(ConverterError::Config(
                    "Hugging Face CLI not found".to_string(),
                ));
            }
            crate::config::HuggingFaceCliStatus::NotLoggedIn => {
                return Err(ConverterError::Config(
                    "Not logged in to Hugging Face".to_string(),
                ));
            }
            crate::config::HuggingFaceCliStatus::LoggedIn(username) => {
                self.ui.success(&format!("HF CLI: Logged in as {}", username));
            }
        }

        let model_name = if let Some(name) = &args.name {
            name.clone()
        } else {
            get_model_name_from_path(&args.model_path)?
        };

        self.ui.info("Push workflow: create -> encrypt -> upload -> hf push");
        self.ui.blank_line();

        // Step 1: Create
        self.ui.info(&format!("Step 1/4: Creating '{}'...", model_name));
        self.handle_create(CreateArgs {
            name: model_name.clone(),
            description: args.description.clone(),
        })
        .await?;

        // Step 2: Encrypt
        self.ui.blank_line();
        self.ui.info(&format!(
            "Step 2/4: Encrypting '{}'...",
            args.model_path.display()
        ));
        self.handle_encrypt(EncryptArgs {
            model_path: args.model_path.clone(),
            name: Some(model_name.clone()),
            output: None,
            no_backup: false,
            files: None,
            exclude: None,
            dry_run: false,
            force: args.force,
        })
        .await?;

        // Step 3: Upload
        self.ui.blank_line();
        self.ui.info("Step 3/4: Uploading to server...");
        self.handle_upload(UploadArgs {
            model_path: args.model_path.clone(),
            name: Some(model_name.clone()),
            force: args.force,
        })
        .await?;

        // Step 4: Push to HF
        self.ui.blank_line();
        self.ui.info("Step 4/4: Pushing to Hugging Face...");
        let hf_repo_name = self.create_hf_repository(&model_name, args.public).await?;
        self.upload_to_hf(&args.model_path, &hf_repo_name).await?;

        self.ui.success("Push completed!");
        Ok(())
    }

    async fn create_hf_repository(&self, model_name: &str, public: bool) -> Result<String> {
        let hf_cli_path = match &self.config.huggingface_cli_path {
            Some(path) => path.clone(),
            None => {
                return Err(ConverterError::Config(
                    "Hugging Face CLI not configured".to_string(),
                ));
            }
        };

        let status = self.config.check_huggingface_cli_status().await?;
        let username = match status {
            crate::config::HuggingFaceCliStatus::LoggedIn(user) => user,
            _ => {
                return Err(ConverterError::Config(
                    "Not logged in to Hugging Face".to_string(),
                ));
            }
        };

        let repo_name = format!("{}/{}", username, model_name);

        let mut cmd = tokio::process::Command::new(&hf_cli_path);
        cmd.arg("repo")
            .arg("create")
            .arg(&repo_name)
            .arg("--repo-type")
            .arg("model");

        if !public {
            cmd.arg("--private");
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| ConverterError::Config(format!("Failed to create HF repo: {}", e)))?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            if error_msg.contains("already exists") {
                self.ui.info(&format!("Repository {} already exists", repo_name));
            } else {
                return Err(ConverterError::Config(format!(
                    "Failed to create HF repo: {}",
                    error_msg
                )));
            }
        } else {
            self.ui.success(&format!(
                "Created HF repository: https://huggingface.co/{}",
                repo_name
            ));
        }

        Ok(repo_name)
    }

    async fn upload_to_hf(&self, model_path: &std::path::Path, repo_name: &str) -> Result<()> {
        let hf_cli_path = match &self.config.huggingface_cli_path {
            Some(path) => path.clone(),
            None => {
                return Err(ConverterError::Config(
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
            .map_err(|e| ConverterError::Config(format!("Failed to upload to HF: {}", e)))?;

        if !status.success() {
            return Err(ConverterError::Config(
                "HF upload failed (non-zero exit)".to_string(),
            ));
        }

        self.ui.success(&format!(
            "Uploaded to https://huggingface.co/{}",
            repo_name
        ));
        Ok(())
    }

    async fn handle_config(&mut self, args: crate::ConfigArgs) -> Result<()> {
        match args.command {
            ConfigCommand::Show => {
                let config_info = vec![
                    ("Endpoint", self.config.endpoint.clone()),
                    ("Timeout", format!("{} seconds", self.config.timeout)),
                    ("Verbose", self.config.verbose.to_string()),
                    ("Storage", self.config.storage_dir.display().to_string()),
                    (
                        "HF CLI",
                        match &self.config.huggingface_cli_path {
                            Some(path) => path.display().to_string(),
                            None => "Auto-detect".to_string(),
                        },
                    ),
                ];
                self.ui.card("Configuration", config_info);
                Ok(())
            }
            #[cfg(debug_assertions)]
            ConfigCommand::SetEndpoint { url } => {
                self.config.endpoint = url.clone();
                self.config.save(&crate::config::default_config_path()).await?;
                self.ui.success(&format!("Endpoint set to: {}", url));
                Ok(())
            }
            ConfigCommand::SetTimeout { seconds } => {
                self.config.timeout = seconds;
                self.config.save(&crate::config::default_config_path()).await?;
                self.ui.success(&format!("Timeout set to: {} seconds", seconds));
                Ok(())
            }
            ConfigCommand::SetVerbose { enabled } => {
                let enabled_bool = match enabled.to_lowercase().as_str() {
                    "true" | "yes" | "on" | "1" => true,
                    "false" | "no" | "off" | "0" => false,
                    _ => {
                        self.ui.error("Invalid value. Use: true/false");
                        return Err(ConverterError::Config("Invalid setting".to_string()));
                    }
                };
                self.config.verbose = enabled_bool;
                self.config.save(&crate::config::default_config_path()).await?;
                self.ui.success(&format!(
                    "Verbose: {}",
                    if enabled_bool { "enabled" } else { "disabled" }
                ));
                Ok(())
            }
            ConfigCommand::Reset => {
                self.config = ConverterConfig::default();
                self.config.save(&crate::config::default_config_path()).await?;
                self.ui.success("Configuration reset");
                Ok(())
            }
            ConfigCommand::SetHuggingfaceCli { path } => {
                if path == "auto" {
                    if let Some(detected_path) = self.config.detect_huggingface_cli().await? {
                        self.ui
                            .success(&format!("Detected HF CLI: {}", detected_path.display()));
                    } else {
                        self.ui.warning("HF CLI not found in PATH");
                    }
                } else {
                    let cli_path = std::path::PathBuf::from(&path);
                    if cli_path.exists() && cli_path.is_file() {
                        self.config.huggingface_cli_path = Some(cli_path.clone());
                        self.config.save(&crate::config::default_config_path()).await?;
                        self.ui
                            .success(&format!("HF CLI set to: {}", cli_path.display()));
                    } else {
                        self.ui.error(&format!("File not found: {}", path));
                        return Err(ConverterError::Config("Invalid path".to_string()));
                    }
                }
                Ok(())
            }
        }
    }

    async fn get_authenticated_client(&mut self) -> Result<Arc<HttpClient>> {
        if let Some(client) = &self.client {
            if client.is_authenticated() {
                return Ok(client.clone());
            }
        }

        let sdk_config = self.config.to_sdk_config();
        let client = HttpClient::new(sdk_config)?;

        if client.is_authenticated() {
            if client.get_current_username().is_some() {
                let client_arc = Arc::new(client);
                self.client = Some(client_arc.clone());
                return Ok(client_arc);
            }
        }

        Err(ConverterError::Authentication(
            "Not authenticated. Run 'koava login' first.".to_string(),
        ))
    }

    async fn check_server_health(&self) -> Result<()> {
        let normalized_endpoint = if self.config.endpoint.ends_with("/api") {
            self.config.endpoint.clone()
        } else if self.config.endpoint.ends_with("/") {
            format!("{}api", self.config.endpoint)
        } else {
            format!("{}/api", self.config.endpoint)
        };

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout))
            .user_agent(&format!("koava/{}", CURRENT_VERSION));

        let endpoint_lower = normalized_endpoint.to_lowercase();
        if endpoint_lower.contains("localhost") || endpoint_lower.contains("127.0.0.1") {
            builder = builder.no_proxy();
        }

        let client = builder
            .build()
            .map_err(|e| ConverterError::Config(format!("Failed to create client: {}", e)))?;

        let health_url = format!("{}/health", normalized_endpoint.trim_end_matches('/'));

        let response = client
            .get(&health_url)
            .send()
            .await
            .map_err(ConverterError::Network)?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ConverterError::Config(format!(
                "Server returned: {}",
                response.status()
            )))
        }
    }
}

fn get_model_name_from_path(path: &std::path::Path) -> Result<String> {
    use std::path::Component;

    let basename_from = |p: &std::path::Path| -> Option<String> {
        p.components().rev().find_map(|c| match c {
            Component::Normal(s) => s.to_str().map(|s| s.to_string()),
            _ => None,
        })
    };

    match path.canonicalize() {
        Ok(canonical_path) => basename_from(&canonical_path)
            .ok_or_else(|| ConverterError::Path("Cannot get model name".to_string())),
        Err(_) => path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ConverterError::Path("Cannot get model name".to_string())),
    }
}

fn parse_model_identifier(
    identifier: &str,
    client: &HttpClient,
) -> Result<(String, String)> {
    if identifier.contains('/') {
        let parts: Vec<&str> = identifier.split('/').collect();
        if parts.len() != 2 {
            return Err(ConverterError::Upload(
                "Invalid format. Use 'username/modelname' or 'modelname'".to_string(),
            ));
        }
        let (provided_username, model_name) = (parts[0], parts[1]);

        let current_username = client.get_current_username().ok_or_else(|| {
            ConverterError::Authentication("Failed to get username".to_string())
        })?;

        if provided_username != current_username {
            return Err(ConverterError::Upload(
                "You can only access your own models".to_string(),
            ));
        }

        Ok((provided_username.to_string(), model_name.to_string()))
    } else {
        let current_username = client.get_current_username().ok_or_else(|| {
            ConverterError::Authentication("Failed to get username".to_string())
        })?;
        Ok((current_username, identifier.to_string()))
    }
}


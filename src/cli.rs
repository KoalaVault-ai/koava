use crate::config::Config;
use crate::encrypt::EncryptService;
use crate::error::Result;
use crate::ui::UI;
use crate::{
    Commands, CreateArgs, EncryptArgs, ListArgs, LoginArgs, RemoveArgs, RestoreArgs, UploadArgs,
};
use std::path::PathBuf;

/// CLI handler for processing commands
pub struct CliHandler {
    config_path: Option<PathBuf>,
    ui: UI,
}

impl CliHandler {
    /// Create a new CLI handler without loading config
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            config_path: None,
            ui: UI::new(),
        }
    }

    /// Create a new CLI handler with a custom config path
    pub fn with_config_path(config_path: Option<PathBuf>) -> Self {
        Self {
            config_path,
            ui: UI::new(),
        }
    }

    /// Load configuration using the handler's config path
    async fn load_config(&self) -> Result<Config> {
        if let Some(path) = &self.config_path {
            Config::load_from(path).await
        } else {
            Config::load().await
        }
    }

    /// Execute a CLI command
    pub async fn execute(&mut self, command: Commands) -> Result<()> {
        match command {
            Commands::Login(args) => self.handle_login(args).await,
            Commands::Logout => self.handle_logout().await,
            Commands::Status => self.handle_status().await,
            Commands::Push(args) => self.handle_push(args).await,
            Commands::Create(args) => self.handle_create(args).await,
            Commands::Encrypt(args) => self.handle_encrypt(args).await,
            Commands::Upload(args) => self.handle_upload(args).await,
            Commands::List(args) => self.handle_list(args).await,
            Commands::Remove(args) => self.handle_remove(args).await,
            Commands::Restore(args) => self.handle_restore(args).await,
            Commands::Config(args) => self.handle_config(args).await,
        }
    }

    /// Handle encrypt command
    async fn handle_encrypt(&mut self, args: EncryptArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config.clone());
        let client = auth_service.get_authenticated_client().await?;
        let encrypt_service = EncryptService::new(config);
        encrypt_service.encrypt(&*client, args).await
    }

    /// Handle restore command
    async fn handle_restore(&mut self, args: RestoreArgs) -> Result<()> {
        let config = self.load_config().await?;
        let encrypt_service = EncryptService::new(config);
        encrypt_service.restore(args).await
    }

    /// Handle upload command - upload encrypted model to server
    async fn handle_upload(&mut self, args: UploadArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config);
        let client = auth_service.get_authenticated_client().await?;
        let service = crate::model::ModelService::new();
        service.upload(client, args).await
    }

    /// Handle remove command
    async fn handle_remove(&mut self, args: RemoveArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config);
        let client = auth_service.get_authenticated_client().await?;
        let service = crate::model::ModelService::new();
        service.remove(client, args).await
    }

    /// Handle status command
    async fn handle_status(&mut self) -> Result<()> {
        let config = self.load_config().await?;
        let service = crate::auth::AuthService::new(config);
        let status_info = service.get_status().await?;

        let mut status_info_vec = vec![
            ("Version", status_info.version),
            (
                "Authentication",
                self.ui.format_auth_status(status_info.authenticated, false),
            ),
        ];

        // Only show username and email if authenticated
        if status_info.authenticated {
            status_info_vec.push(("Username", self.ui.format_user_field(status_info.username)));
            status_info_vec.push(("Email", self.ui.format_user_field(status_info.email)));
        }

        status_info_vec.push((
            "Server",
            if status_info.server_connected {
                self.ui.format_server_status(true)
            } else {
                format!(
                    "{} ({})",
                    self.ui.format_server_status(false),
                    status_info.server_status_msg
                )
            },
        ));
        status_info_vec.push(("Hugging Face CLI", status_info.hf_status_str));

        self.ui.card("Status", status_info_vec);
        Ok(())
    }

    /// Handle login command
    async fn handle_login(&mut self, args: LoginArgs) -> Result<()> {
        let config = self.load_config().await?;
        let service = crate::auth::AuthService::new(config);
        let (_username, _client) = service.login(args).await?;
        Ok(())
    }

    /// Handle logout command
    async fn handle_logout(&mut self) -> Result<()> {
        let config = self.load_config().await?;
        let service = crate::auth::AuthService::new(config);
        service.logout(None).await?;
        Ok(())
    }

    /// Handle list command - list files for a model on server
    async fn handle_list(&mut self, args: ListArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config);
        let client = auth_service.get_authenticated_client().await?;
        let service = crate::model::ModelService::new();
        service.list(client, args).await
    }

    /// Handle create command
    async fn handle_create(&mut self, args: CreateArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config);
        let client = auth_service.get_authenticated_client().await?;
        let service = crate::model::ModelService::new();
        service.create(client, args).await
    }

    /// Handle push command: create -> encrypt -> upload -> hf create repo -> upload to hf -> update model
    async fn handle_push(&mut self, args: crate::PushArgs) -> Result<()> {
        let config = self.load_config().await?;
        let auth_service = crate::auth::AuthService::new(config.clone());
        let client = auth_service.get_authenticated_client().await?;
        let mut service = crate::push::PushService::new(config);
        service.push(client, args).await
    }

    /// Handle config command
    async fn handle_config(&mut self, args: crate::ConfigArgs) -> Result<()> {
        let config = self.load_config().await?;
        let mut service = if let Some(path) = self.config_path.clone() {
            crate::config::ConfigService::with_config_path(config, path)
        } else {
            crate::config::ConfigService::new(config)
        };
        service.handle_config(args).await?;
        Ok(())
    }
}

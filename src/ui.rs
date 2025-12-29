//! UI utilities for koava CLI

use console::Term;
use owo_colors::OwoColorize;
use unicode_width::UnicodeWidthStr;

use crate::config::HuggingFaceCliStatus;
use crate::model::format_bytes;

/// UI helper
pub struct UI {
    term: Term,
}

impl UI {
    pub fn new() -> Self {
        Self { term: Term::stdout() }
    }

    pub fn success(&self, message: &str) {
        println!("{}", message.green().bold());
    }

    pub fn error(&self, message: &str) {
        eprintln!("{}", message.red().bold());
    }

    pub fn warning(&self, message: &str) {
        println!("{}", message.yellow().bold());
    }

    pub fn info(&self, message: &str) {
        println!("{}", message.blue().bold());
    }

    pub fn format_auth_status(&self, authenticated: bool, expired: bool) -> String {
        if authenticated {
            "Authenticated".green().to_string()
        } else if expired {
            "Token expired".yellow().to_string()
        } else {
            "Not authenticated".red().to_string()
        }
    }

    pub fn format_server_status(&self, connected: bool) -> String {
        if connected {
            "Connected".green().to_string()
        } else {
            "Connection failed".red().to_string()
        }
    }

    pub fn format_huggingface_cli_status(&self, status: &HuggingFaceCliStatus) -> String {
        match status {
            HuggingFaceCliStatus::NotFound => "Not found".red().to_string(),
            HuggingFaceCliStatus::NotLoggedIn => "Found (not logged in)".yellow().to_string(),
            HuggingFaceCliStatus::LoggedIn(username) => {
                format!("{} {}", "Logged in as".green(), username)
            }
        }
    }

    pub fn format_user_field(&self, value: Option<String>) -> String {
        value.unwrap_or_else(|| "-".to_string())
    }

    pub fn blank_line(&self) {
        println!();
    }

    pub fn card(&self, title: &str, content: Vec<(&str, String)>) {
        let term_width = self.term.size().1 as usize;
        let card_width = term_width.saturating_sub(4).max(50).min(80);

        println!("╭{}╮", "─".repeat(card_width - 2));
        let title_width = title.width();
        let title_spaces = card_width.saturating_sub(title_width + 4);
        println!("│ {} {}│", title.cyan().bold(), " ".repeat(title_spaces));
        println!("├{}┤", "─".repeat(card_width - 2));

        for (label, value) in content {
            let label_plain = console::strip_ansi_codes(label);
            let value_plain = console::strip_ansi_codes(&value);

            let label_width = label_plain.width();
            let value_width = value_plain.width();
            let content_width = label_width + value_width + 4;

            let spaces = if content_width < card_width - 1 {
                card_width - content_width - 1
            } else {
                1
            };

            println!("│ {}: {}{}│", label.dimmed(), value, " ".repeat(spaces));
        }

        println!("╰{}╯", "─".repeat(card_width - 2));
        println!();
    }

    pub fn width(&self) -> usize {
        self.term.size().1 as usize
    }
}

impl Default for UI {
    fn default() -> Self {
        Self::new()
    }
}

/// Format file size with color
pub fn format_size_colored(bytes: u64) -> String {
    let formatted = format_bytes(bytes);

    if bytes < 1024 * 1024 {
        formatted.green().to_string()
    } else if bytes < 1024 * 1024 * 1024 {
        formatted.yellow().to_string()
    } else {
        formatted.red().to_string()
    }
}

/// Create a progress bar
pub fn create_progress_bar(len: u64, message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(len);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{elapsed_precise:.dim}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb.set_message(message.to_string());
    pb
}


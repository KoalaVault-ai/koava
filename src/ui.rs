use console::{strip_ansi_codes, Term};
use owo_colors::OwoColorize;
use unicode_width::UnicodeWidthStr;

use std::default::Default;
/// Enhanced UI utilities
pub struct UI {
    term: Term,
}

impl UI {
    pub fn new() -> Self {
        Self {
            term: Term::stdout(),
        }
    }

    /// Helper method to conditionally apply color based on terminal support
    fn colorize<F>(&self, text: &str, color_fn: F) -> String
    where
        F: FnOnce(&str) -> String,
    {
        if self.supports_color() {
            color_fn(text)
        } else {
            text.to_string()
        }
    }

    /// Print a success message (color only if supported)
    pub fn success(&self, message: &str) {
        let output = self.colorize(message, |m| m.green().bold().to_string());
        println!("{}", output);
    }

    /// Print an error message (color only if supported)
    pub fn error(&self, message: &str) {
        let output = self.colorize(message, |m| m.red().bold().to_string());
        eprintln!("{}", output);
    }

    /// Print a warning message (color only if supported)
    pub fn warning(&self, message: &str) {
        let output = self.colorize(message, |m| m.yellow().bold().to_string());
        println!("{}", output);
    }

    /// Print an info message (color only if supported)
    pub fn info(&self, message: &str) {
        let output = self.colorize(message, |m| m.blue().bold().to_string());
        println!("{}", output);
    }

    /// Format authentication status with appropriate color (if supported)
    pub fn format_auth_status(&self, authenticated: bool, expired: bool) -> String {
        let text = if authenticated {
            "Authenticated"
        } else if expired {
            "Token expired"
        } else {
            "Not authenticated"
        };

        if self.supports_color() {
            if authenticated {
                text.green().to_string()
            } else if expired {
                text.yellow().to_string()
            } else {
                text.red().to_string()
            }
        } else {
            text.to_string()
        }
    }

    /// Format server connection status with appropriate color (if supported)
    pub fn format_server_status(&self, connected: bool) -> String {
        let text = if connected {
            "Connected"
        } else {
            "Connection failed"
        };
        if self.supports_color() {
            if connected {
                text.green().to_string()
            } else {
                text.red().to_string()
            }
        } else {
            text.to_string()
        }
    }

    /// Format Hugging Face CLI status with appropriate color (if supported)
    pub fn format_huggingface_cli_status(
        &self,
        status: &crate::huggingface::HuggingFaceCliStatus,
    ) -> String {
        let supports_color = self.supports_color();
        match status {
            crate::huggingface::HuggingFaceCliStatus::NotFound => {
                if supports_color {
                    "Not found".red().to_string()
                } else {
                    "Not found".to_string()
                }
            }
            crate::huggingface::HuggingFaceCliStatus::NotLoggedIn => {
                if supports_color {
                    "Found (not logged in)".yellow().to_string()
                } else {
                    "Found (not logged in)".to_string()
                }
            }
            crate::huggingface::HuggingFaceCliStatus::LoggedIn(username) => {
                if supports_color {
                    format!("{} {}", "Logged in as".green(), username)
                } else {
                    format!("Logged in as {}", username)
                }
            }
        }
    }

    /// Format user field with fallback for missing data
    pub fn format_user_field(&self, value: Option<String>) -> String {
        value.unwrap_or_else(|| "-".to_string())
    }

    /// Print a blank line for spacing
    pub fn blank_line(&self) {
        println!();
    }

    /// Print a section header
    pub fn header(&self, title: &str) {
        let term_width = self.width();
        let title_len = title.len() + 4; // 2 spaces on each side
        let line_len = if term_width > title_len {
            (term_width - title_len) / 2
        } else {
            0
        };

        let line = "═".repeat(line_len);
        let supports_color = self.supports_color();

        println!();
        if supports_color {
            println!("{} {} {}", line.cyan(), title.cyan().bold(), line.cyan());
        } else {
            println!("{} {} {}", line, title, line);
        }
        println!();
    }

    /// Print a separator line
    pub fn separator(&self) {
        let width = self.width();
        let line = "─".repeat(width.min(80));
        if self.supports_color() {
            println!("{}", line.dimmed());
        } else {
            println!("{}", line);
        }
    }

    /// Print a status with colored indicator (no icons, color only if supported)
    pub fn status(&self, label: &str, status: &str, is_good: bool) {
        if self.supports_color() {
            if is_good {
                println!("{}: {}", label.bold(), status.green());
            } else {
                println!("{}: {}", label.bold(), status.red());
            }
        } else {
            println!("{}: {}", label, status);
        }
    }

    /// Create a card-style display for information
    pub fn card(&self, title: &str, content: Vec<(&str, String)>) {
        let term_width = self.width();
        let card_width = term_width
            .saturating_sub(4) // Leave more space for terminal margins
            .clamp(50, 80); // Minimum and maximum width

        let supports_color = self.supports_color();

        // Card header
        println!("╭{}╮", "─".repeat(card_width - 2));
        let title_width = title.width();
        let title_spaces = card_width.saturating_sub(title_width + 4);
        if supports_color {
            println!("│ {} {}│", title.cyan().bold(), " ".repeat(title_spaces));
        } else {
            println!("│ {} {}│", title, " ".repeat(title_spaces));
        }
        println!("├{}┤", "─".repeat(card_width - 2));

        // Card content
        for (label, value) in content {
            // Strip ANSI codes for width calculations
            let label_plain = strip_ansi_codes(label);
            let value_plain = strip_ansi_codes(&value);

            let label_width = label_plain.width();
            let value_width = value_plain.width();
            let content_width = label_width + value_width + 4; // ": " + 2 spaces padding

            let spaces = if content_width < card_width - 1 {
                card_width - content_width - 1
            } else {
                1 // At least one space
            };

            if supports_color {
                println!("│ {}: {}{}│", label.dimmed(), value, " ".repeat(spaces));
            } else {
                println!("│ {}: {}{}│", label, value, " ".repeat(spaces));
            }
        }

        // Card footer
        println!("╰{}╯", "─".repeat(card_width - 2));
        println!();
    }

    /// Get terminal width for responsive layout
    pub fn width(&self) -> usize {
        self.term.size().1 as usize
    }

    /// Check if terminal supports color
    pub fn supports_color(&self) -> bool {
        self.term.features().colors_supported()
    }

    /// Print a box with content
    pub fn box_content(&self, title: &str, lines: Vec<String>) {
        let max_line_length = lines.iter().map(|l| l.len()).max().unwrap_or(0);
        let box_width = (max_line_length + 4).max(title.len() + 4);
        let supports_color = self.supports_color();

        println!("┌{}┐", "─".repeat(box_width - 2));
        if supports_color {
            println!(
                "│ {} {}│",
                title.cyan().bold(),
                " ".repeat(box_width - title.len() - 4)
            );
        } else {
            println!("│ {} {}│", title, " ".repeat(box_width - title.len() - 4));
        }

        if !lines.is_empty() {
            println!("├{}┤", "─".repeat(box_width - 2));
            for line in lines {
                println!("│ {}{} │", line, " ".repeat(box_width - line.len() - 4));
            }
        }

        println!("└{}┘", "─".repeat(box_width - 2));
    }
}

impl Default for UI {
    fn default() -> Self {
        Self::new()
    }
}

/// Format file size in a human readable way with colors (if supported)
pub fn format_size_colored(bytes: u64) -> String {
    let formatted = crate::format_bytes(bytes);
    let supports_color = Term::stdout().features().colors_supported();

    if supports_color {
        if bytes < crate::utils::MB {
            formatted.green().to_string()
        } else if bytes < crate::utils::GB {
            formatted.yellow().to_string()
        } else {
            formatted.red().to_string()
        }
    } else {
        formatted
    }
}

/// Create a progress bar with modern styling
pub fn create_progress_bar(len: u64, message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new(len);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{elapsed_precise:.dim}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  ")
    );
    pb.set_message(message.to_string());
    pb
}

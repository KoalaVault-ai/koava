//! Version information

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn format_version_info() -> String {
    format!("koava v{}", CURRENT_VERSION)
}


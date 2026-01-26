//! Template files for KoalaVault encrypted models
//!
//! This module contains template files that are embedded into the binary
//! for generating README and LICENSE files for encrypted models.

/// Template for README.md files of encrypted models
pub const README_TEMPLATE: &str = include_str!("../templates/README_ENCRYPTED_MODEL.md");

/// Template for LICENSE files of encrypted models
pub const LICENSE_TEMPLATE: &str = include_str!("../templates/KOALAVAULT_PROPRIETARY_LICENSE.txt");

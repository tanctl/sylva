use crate::error::{Result, SylvaError};
use crate::storage::compression::{CompressionAlgorithm, CompressionConfig};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub default_hash: Option<String>,
    pub cache_size: Option<usize>,
    pub compression_level: Option<i32>,
    pub compression_algorithm: Option<String>,
    pub enable_compression: Option<bool>,
    pub ledger_format: Option<String>,

    // Tree configuration
    pub default_tree_type: Option<String>,
    pub tree_auto_selection: Option<bool>,
    pub tree_migration_enabled: Option<bool>,
    pub tree_validation_level: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_hash: Some("blake3".to_string()),
            cache_size: Some(1000),
            compression_level: Some(3),
            compression_algorithm: Some("zstd".to_string()),
            enable_compression: Some(false),
            ledger_format: Some("json".to_string()),

            // Tree defaults
            default_tree_type: Some("binary".to_string()),
            tree_auto_selection: Some(true),
            tree_migration_enabled: Some(true),
            tree_validation_level: Some("standard".to_string()),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let global_config = Self::load_global().unwrap_or_default();
        let project_config = Self::load_project().unwrap_or_default();

        Ok(Self::merge(global_config, project_config))
    }

    pub fn load_global() -> Result<Self> {
        let config_path = Self::global_config_path()?;
        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to read global config from {}: {}",
                config_path.display(),
                e
            ),
        })?;

        let config: Self = toml::from_str(&content).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to parse global config from {}: {}",
                config_path.display(),
                e
            ),
        })?;

        Ok(config)
    }

    pub fn load_project() -> Result<Self> {
        let config_path = Self::project_config_path()?;
        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to read project config from {}: {}",
                config_path.display(),
                e
            ),
        })?;

        let config: Self = toml::from_str(&content).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to parse project config from {}: {}",
                config_path.display(),
                e
            ),
        })?;

        Ok(config)
    }

    pub fn save_global(&self) -> Result<()> {
        let config_path = Self::global_config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).map_err(|e| SylvaError::ConfigError {
                message: format!(
                    "Failed to create config directory {}: {}",
                    parent.display(),
                    e
                ),
            })?;
        }

        let content = toml::to_string_pretty(self).map_err(|e| SylvaError::ConfigError {
            message: format!("Failed to serialize global config: {}", e),
        })?;

        fs::write(&config_path, content).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to write global config to {}: {}",
                config_path.display(),
                e
            ),
        })?;

        Ok(())
    }

    pub fn save_project(&self) -> Result<()> {
        let config_path = Self::project_config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).map_err(|e| SylvaError::ConfigError {
                message: format!(
                    "Failed to create config directory {}: {}",
                    parent.display(),
                    e
                ),
            })?;
        }

        let content = toml::to_string_pretty(self).map_err(|e| SylvaError::ConfigError {
            message: format!("Failed to serialize project config: {}", e),
        })?;

        fs::write(&config_path, content).map_err(|e| SylvaError::ConfigError {
            message: format!(
                "Failed to write project config to {}: {}",
                config_path.display(),
                e
            ),
        })?;

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(hash) = &self.default_hash {
            if !["blake3", "sha256", "keccak"].contains(&hash.as_str()) {
                return Err(SylvaError::ConfigError {
                    message: format!(
                        "Invalid default_hash: {}. Must be one of: blake3, sha256, keccak",
                        hash
                    ),
                });
            }
        }

        if let Some(cache_size) = self.cache_size {
            if cache_size == 0 {
                return Err(SylvaError::ConfigError {
                    message: "cache_size must be greater than 0".to_string(),
                });
            }
        }

        if let Some(compression_level) = self.compression_level {
            if !(1..=22).contains(&compression_level) {
                return Err(SylvaError::ConfigError {
                    message: "compression_level must be between 1 and 22 for zstd".to_string(),
                });
            }
        }

        if let Some(algorithm) = &self.compression_algorithm {
            if !["zstd", "none"].contains(&algorithm.as_str()) {
                return Err(SylvaError::ConfigError {
                    message: format!(
                        "Invalid compression_algorithm: {}. Must be one of: zstd, none",
                        algorithm
                    ),
                });
            }
        }

        if let Some(format) = &self.ledger_format {
            if !["json", "binary", "compressed-json", "compressed-binary"]
                .contains(&format.as_str())
            {
                return Err(SylvaError::ConfigError {
                    message: format!(
                        "Invalid ledger_format: {}. Must be one of: json, binary, compressed-json, compressed-binary",
                        format
                    ),
                });
            }
        }

        // Validate tree configuration
        if let Some(tree_type) = &self.default_tree_type {
            if !["binary", "sparse", "patricia"].contains(&tree_type.as_str()) {
                return Err(SylvaError::ConfigError {
                    message: format!(
                        "Invalid default_tree_type: {}. Must be one of: binary, sparse, patricia",
                        tree_type
                    ),
                });
            }
        }

        if let Some(validation_level) = &self.tree_validation_level {
            if !["strict", "standard", "lenient", "disabled"].contains(&validation_level.as_str()) {
                return Err(SylvaError::ConfigError {
                    message: format!(
                        "Invalid tree_validation_level: {}. Must be one of: strict, standard, lenient, disabled",
                        validation_level
                    ),
                });
            }
        }

        Ok(())
    }

    fn merge(global: Self, project: Self) -> Self {
        Self {
            default_hash: project.default_hash.or(global.default_hash),
            cache_size: project.cache_size.or(global.cache_size),
            compression_level: project.compression_level.or(global.compression_level),
            compression_algorithm: project
                .compression_algorithm
                .or(global.compression_algorithm),
            enable_compression: project.enable_compression.or(global.enable_compression),
            ledger_format: project.ledger_format.or(global.ledger_format),

            // Tree merging - project config takes precedence
            default_tree_type: project.default_tree_type.or(global.default_tree_type),
            tree_auto_selection: project.tree_auto_selection.or(global.tree_auto_selection),
            tree_migration_enabled: project
                .tree_migration_enabled
                .or(global.tree_migration_enabled),
            tree_validation_level: project
                .tree_validation_level
                .or(global.tree_validation_level),
        }
    }

    fn global_config_path() -> Result<PathBuf> {
        let proj_dirs =
            ProjectDirs::from("", "", "sylva").ok_or_else(|| SylvaError::ConfigError {
                message: "Failed to get project directories".to_string(),
            })?;

        Ok(proj_dirs.config_dir().join("config.toml"))
    }

    fn project_config_path() -> Result<PathBuf> {
        let current_dir = std::env::current_dir().map_err(|e| SylvaError::ConfigError {
            message: format!("Failed to get current directory: {}", e),
        })?;

        Ok(current_dir.join(".sylva").join("config.toml"))
    }

    pub fn get_default_hash(&self) -> String {
        self.default_hash
            .as_ref()
            .unwrap_or(&"blake3".to_string())
            .clone()
    }

    pub fn get_cache_size(&self) -> usize {
        self.cache_size.unwrap_or(1000)
    }

    pub fn get_compression_level(&self) -> i32 {
        self.compression_level.unwrap_or(3)
    }

    pub fn get_compression_algorithm(&self) -> String {
        self.compression_algorithm
            .as_ref()
            .unwrap_or(&"zstd".to_string())
            .clone()
    }

    pub fn get_enable_compression(&self) -> bool {
        self.enable_compression.unwrap_or(false)
    }

    pub fn get_ledger_format(&self) -> String {
        self.ledger_format
            .as_ref()
            .unwrap_or(&"json".to_string())
            .clone()
    }

    /// Convert config to CompressionConfig for storage use
    pub fn to_compression_config(&self) -> Result<CompressionConfig> {
        let algorithm = match self.get_compression_algorithm().as_str() {
            "zstd" => CompressionAlgorithm::Zstd,
            "none" => CompressionAlgorithm::None,
            _ => CompressionAlgorithm::Zstd, // Default fallback
        };

        CompressionConfig::new(algorithm, self.get_compression_level())
    }

    // Tree configuration getters
    pub fn get_default_tree_type(&self) -> String {
        self.default_tree_type
            .as_ref()
            .unwrap_or(&"binary".to_string())
            .clone()
    }

    pub fn get_tree_auto_selection(&self) -> bool {
        self.tree_auto_selection.unwrap_or(true)
    }

    pub fn get_tree_migration_enabled(&self) -> bool {
        self.tree_migration_enabled.unwrap_or(true)
    }

    pub fn get_tree_validation_level(&self) -> String {
        self.tree_validation_level
            .as_ref()
            .unwrap_or(&"standard".to_string())
            .clone()
    }

    /// Get tree type as TreeType enum (requires tree module import)
    pub fn get_tree_type_enum(&self) -> Result<crate::tree::TreeType> {
        self.get_default_tree_type().parse()
    }

    /// Update tree configuration
    pub fn set_default_tree_type(&mut self, tree_type: &str) -> Result<()> {
        if !["binary", "sparse", "patricia"].contains(&tree_type) {
            return Err(SylvaError::ConfigError {
                message: format!("Invalid tree type: {}", tree_type),
            });
        }
        self.default_tree_type = Some(tree_type.to_string());
        Ok(())
    }

    pub fn set_tree_auto_selection(&mut self, enabled: bool) {
        self.tree_auto_selection = Some(enabled);
    }

    pub fn set_tree_migration_enabled(&mut self, enabled: bool) {
        self.tree_migration_enabled = Some(enabled);
    }

    pub fn set_tree_validation_level(&mut self, level: &str) -> Result<()> {
        if !["strict", "standard", "lenient", "disabled"].contains(&level) {
            return Err(SylvaError::ConfigError {
                message: format!("Invalid validation level: {}", level),
            });
        }
        self.tree_validation_level = Some(level.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.default_hash, Some("blake3".to_string()));
        assert_eq!(config.cache_size, Some(1000));
        assert_eq!(config.compression_level, Some(3));
        assert_eq!(config.compression_algorithm, Some("zstd".to_string()));
        assert_eq!(config.enable_compression, Some(false));
        assert_eq!(config.ledger_format, Some("json".to_string()));

        // Test tree defaults
        assert_eq!(config.default_tree_type, Some("binary".to_string()));
        assert_eq!(config.tree_auto_selection, Some(true));
        assert_eq!(config.tree_migration_enabled, Some(true));
        assert_eq!(config.tree_validation_level, Some("standard".to_string()));
    }

    #[test]
    fn test_config_merge() {
        let global = Config {
            default_hash: Some("sha256".to_string()),
            cache_size: Some(500),
            compression_level: Some(6),
            compression_algorithm: Some("zstd".to_string()),
            enable_compression: Some(true),
            ledger_format: Some("binary".to_string()),
            default_tree_type: Some("sparse".to_string()),
            tree_auto_selection: Some(false),
            tree_migration_enabled: Some(false),
            tree_validation_level: Some("strict".to_string()),
        };

        let project = Config {
            default_hash: Some("blake3".to_string()),
            cache_size: None,
            compression_level: Some(9),
            compression_algorithm: None,
            enable_compression: Some(false),
            ledger_format: None,
            default_tree_type: Some("patricia".to_string()),
            tree_auto_selection: Some(true),
            tree_migration_enabled: None,
            tree_validation_level: None,
        };

        let merged = Config::merge(global, project);
        assert_eq!(merged.default_hash, Some("blake3".to_string()));
        assert_eq!(merged.cache_size, Some(500));
        assert_eq!(merged.compression_level, Some(9));
        assert_eq!(merged.compression_algorithm, Some("zstd".to_string()));
        assert_eq!(merged.enable_compression, Some(false));
        assert_eq!(merged.ledger_format, Some("binary".to_string()));

        // Test tree field merging
        assert_eq!(merged.default_tree_type, Some("patricia".to_string()));
        assert_eq!(merged.tree_auto_selection, Some(true));
        assert_eq!(merged.tree_migration_enabled, Some(false)); // from global
        assert_eq!(merged.tree_validation_level, Some("strict".to_string())); // from global
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.default_hash = Some("invalid".to_string());
        assert!(config.validate().is_err());

        config.default_hash = Some("blake3".to_string());
        config.cache_size = Some(0);
        assert!(config.validate().is_err());

        config.cache_size = Some(100);
        config.compression_level = Some(25);
        assert!(config.validate().is_err());

        config.compression_level = Some(5);
        config.compression_algorithm = Some("invalid".to_string());
        assert!(config.validate().is_err());

        config.compression_algorithm = Some("zstd".to_string());
        config.ledger_format = Some("invalid".to_string());
        assert!(config.validate().is_err());

        // Test tree validation
        config.ledger_format = Some("json".to_string());
        config.default_tree_type = Some("invalid_tree".to_string());
        assert!(config.validate().is_err());

        config.default_tree_type = Some("binary".to_string());
        config.tree_validation_level = Some("invalid_level".to_string());
        assert!(config.validate().is_err());

        config.tree_validation_level = Some("standard".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_getters() {
        let config = Config {
            default_hash: None,
            cache_size: None,
            compression_level: None,
            compression_algorithm: None,
            enable_compression: None,
            ledger_format: None,
            default_tree_type: None,
            tree_auto_selection: None,
            tree_migration_enabled: None,
            tree_validation_level: None,
        };

        assert_eq!(config.get_default_hash(), "blake3");
        assert_eq!(config.get_cache_size(), 1000);
        assert_eq!(config.get_compression_level(), 3);
        assert_eq!(config.get_compression_algorithm(), "zstd");
        assert_eq!(config.get_enable_compression(), false);
        assert_eq!(config.get_ledger_format(), "json");

        // Test tree getters with defaults
        assert_eq!(config.get_default_tree_type(), "binary");
        assert!(config.get_tree_auto_selection());
        assert!(config.get_tree_migration_enabled());
        assert_eq!(config.get_tree_validation_level(), "standard");

        let config = Config {
            default_hash: Some("sha256".to_string()),
            cache_size: Some(2000),
            compression_level: Some(9),
            compression_algorithm: Some("zstd".to_string()),
            enable_compression: Some(true),
            ledger_format: Some("binary".to_string()),
            default_tree_type: Some("sparse".to_string()),
            tree_auto_selection: Some(false),
            tree_migration_enabled: Some(false),
            tree_validation_level: Some("strict".to_string()),
        };

        assert_eq!(config.get_default_hash(), "sha256");
        assert_eq!(config.get_cache_size(), 2000);
        assert_eq!(config.get_compression_level(), 9);
        assert_eq!(config.get_compression_algorithm(), "zstd");
        assert!(config.get_enable_compression());
        assert_eq!(config.get_ledger_format(), "binary");

        // Test tree getters with values
        assert_eq!(config.get_default_tree_type(), "sparse");
        assert!(!config.get_tree_auto_selection());
        assert!(!config.get_tree_migration_enabled());
        assert_eq!(config.get_tree_validation_level(), "strict");
    }

    #[test]
    fn test_compression_config_conversion() {
        let config = Config {
            default_hash: None,
            cache_size: None,
            compression_level: Some(5),
            compression_algorithm: Some("zstd".to_string()),
            enable_compression: Some(true),
            ledger_format: None,
            default_tree_type: None,
            tree_auto_selection: None,
            tree_migration_enabled: None,
            tree_validation_level: None,
        };

        let compression_config = config.to_compression_config().unwrap();
        assert_eq!(compression_config.algorithm, CompressionAlgorithm::Zstd);
        assert_eq!(compression_config.level, 5);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, deserialized);
    }
}

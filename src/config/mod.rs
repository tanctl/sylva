//! git-like configuration system for sylva

mod legacy;

// re-export legacy config for backward compatibility
pub use legacy::{
    BackupConfig, Config as LegacyConfig, HashAlgorithm as LegacyHashAlgorithm, HashingConfig,
    PerformanceConfig, ProofConfig, StorageBackend, StorageConfig, WorkspaceConfig,
};

use crate::error::{Result, SylvaError};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// main sylva configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// default hash algorithm to use
    pub default_hash: String,
    /// cache size in bytes
    pub cache_size: u64,
    /// compression level (0-9)
    pub compression_level: u8,
    /// ledger format version
    pub ledger_format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_hash: "blake3".to_string(),
            cache_size: 100 * 1024 * 1024, // 100MB
            compression_level: 6,
            ledger_format: "v1".to_string(),
        }
    }
}

/// configuration sources and priority
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigSource {
    /// built-in defaults
    Default,
    /// global config at ~/.sylva/config.toml
    Global,
    /// project config at .sylva/config.toml
    Project,
}

/// configuration manager with git-like hierarchy
#[derive(Debug)]
pub struct ConfigManager {
    /// loaded configuration
    pub config: Config,
    /// sources used to build config
    pub sources: Vec<ConfigSource>,
    /// project directory if any
    pub project_dir: Option<PathBuf>,
}

impl Config {
    /// validate configuration values
    pub fn validate(&self) -> Result<()> {
        // validate hash algorithm
        let valid_hashes = ["blake3", "sha256", "keccak256"];
        if !valid_hashes.contains(&self.default_hash.as_str()) {
            return Err(SylvaError::config_error(format!(
                "Invalid hash algorithm '{}'. Valid options: {}",
                self.default_hash,
                valid_hashes.join(", ")
            )));
        }

        // validate cache size (at least 1MB, max 10GB)
        if self.cache_size < 1024 * 1024 {
            return Err(SylvaError::config_error(
                "Cache size must be at least 1MB (1048576 bytes)".to_string(),
            ));
        }
        if self.cache_size > 10 * 1024 * 1024 * 1024 {
            return Err(SylvaError::config_error(
                "Cache size must not exceed 10GB (10737418240 bytes)".to_string(),
            ));
        }

        // validate compression level (0-9)
        if self.compression_level > 9 {
            return Err(SylvaError::config_error(format!(
                "Compression level must be 0-9, got {}",
                self.compression_level
            )));
        }

        // validate ledger format
        let valid_formats = ["v1"];
        if !valid_formats.contains(&self.ledger_format.as_str()) {
            return Err(SylvaError::config_error(format!(
                "Invalid ledger format '{}'. Valid options: {}",
                self.ledger_format,
                valid_formats.join(", ")
            )));
        }

        Ok(())
    }

    /// merge another config into this one (other takes precedence)
    pub fn merge(&mut self, other: &Config) {
        self.default_hash = other.default_hash.clone();
        self.cache_size = other.cache_size;
        self.compression_level = other.compression_level;
        self.ledger_format = other.ledger_format.clone();
    }

    /// load config from toml file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).map_err(|e| {
            SylvaError::config_error(format!(
                "Failed to read config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            SylvaError::config_error(format!(
                "Failed to parse config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        config.validate()?;
        Ok(config)
    }

    /// save config to toml file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.validate()?;

        // ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SylvaError::config_error(format!(
                    "Failed to create config directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| SylvaError::config_error(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(&path, content).map_err(|e| {
            SylvaError::config_error(format!(
                "Failed to write config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Ok(())
    }
}

impl ConfigManager {
    /// create config manager and load configuration hierarchy
    pub fn new() -> Result<Self> {
        let mut manager = Self {
            config: Config::default(),
            sources: vec![ConfigSource::Default],
            project_dir: None,
        };

        manager.load_config_hierarchy()?;
        Ok(manager)
    }

    /// create config manager for specific project directory
    pub fn for_project<P: AsRef<Path>>(project_dir: P) -> Result<Self> {
        let mut manager = Self {
            config: Config::default(),
            sources: vec![ConfigSource::Default],
            project_dir: Some(project_dir.as_ref().to_path_buf()),
        };

        manager.load_config_hierarchy()?;
        Ok(manager)
    }

    /// get global config directory path
    pub fn global_config_dir() -> Result<PathBuf> {
        ProjectDirs::from("", "", "sylva")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .ok_or_else(|| {
                SylvaError::config_error("Unable to determine global config directory".to_string())
            })
    }

    /// get global config file path
    pub fn global_config_path() -> Result<PathBuf> {
        Ok(Self::global_config_dir()?.join("config.toml"))
    }

    /// get project config file path for given directory
    pub fn project_config_path<P: AsRef<Path>>(project_dir: P) -> PathBuf {
        project_dir.as_ref().join(".sylva").join("config.toml")
    }

    /// find project root by looking for .sylva directory
    pub fn find_project_root() -> Option<PathBuf> {
        let mut current = std::env::current_dir().ok()?;

        loop {
            let sylva_dir = current.join(".sylva");
            if sylva_dir.exists() && sylva_dir.is_dir() {
                return Some(current);
            }

            if !current.pop() {
                break;
            }
        }

        None
    }

    /// load configuration hierarchy (default -> global -> project)
    fn load_config_hierarchy(&mut self) -> Result<()> {
        self.config = Config::default();
        self.sources = vec![ConfigSource::Default];

        // try to load global config
        let global_path = Self::global_config_path()?;
        if global_path.exists() {
            match Config::load_from_file(&global_path) {
                Ok(global_config) => {
                    self.config.merge(&global_config);
                    self.sources.push(ConfigSource::Global);
                }
                Err(e) => {
                    return Err(SylvaError::config_error(format!(
                        "Failed to load global config: {}",
                        e
                    )));
                }
            }
        }

        // try to load project config
        let project_dir = self.project_dir.clone().or_else(Self::find_project_root);
        if let Some(project_dir) = project_dir {
            let project_path = Self::project_config_path(&project_dir);
            if project_path.exists() {
                match Config::load_from_file(&project_path) {
                    Ok(project_config) => {
                        self.config.merge(&project_config);
                        self.sources.push(ConfigSource::Project);
                    }
                    Err(e) => {
                        return Err(SylvaError::config_error(format!(
                            "Failed to load project config: {}",
                            e
                        )));
                    }
                }
            }
        }

        // final validation
        self.config.validate()?;
        Ok(())
    }

    /// save global config
    pub fn save_global_config(&self) -> Result<()> {
        let path = Self::global_config_path()?;
        self.config.save_to_file(path)
    }

    /// save project config for current or specified project
    pub fn save_project_config<P: AsRef<Path>>(&self, project_dir: Option<P>) -> Result<()> {
        let project_dir = if let Some(dir) = project_dir {
            dir.as_ref().to_path_buf()
        } else if let Some(ref dir) = self.project_dir {
            dir.clone()
        } else {
            Self::find_project_root()
                .ok_or_else(|| SylvaError::config_error("No project directory found".to_string()))?
        };

        let path = Self::project_config_path(&project_dir);
        self.config.save_to_file(path)
    }

    /// get effective configuration value with source information
    pub fn get_config_with_source(&self) -> (&Config, &[ConfigSource]) {
        (&self.config, &self.sources)
    }

    /// reload configuration hierarchy
    pub fn reload(&mut self) -> Result<()> {
        self.load_config_hierarchy()
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            config: Config::default(),
            sources: vec![ConfigSource::Default],
            project_dir: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.default_hash, "blake3");
        assert_eq!(config.cache_size, 100 * 1024 * 1024);
        assert_eq!(config.compression_level, 6);
        assert_eq!(config.ledger_format, "v1");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();

        // test invalid hash
        config.default_hash = "invalid".to_string();
        assert!(config.validate().is_err());

        config.default_hash = "blake3".to_string();
        assert!(config.validate().is_ok());

        // test invalid cache size
        config.cache_size = 1024; // too small
        assert!(config.validate().is_err());

        config.cache_size = 11 * 1024 * 1024 * 1024; // too large
        assert!(config.validate().is_err());

        config.cache_size = 100 * 1024 * 1024;
        assert!(config.validate().is_ok());

        // test invalid compression level
        config.compression_level = 10;
        assert!(config.validate().is_err());

        config.compression_level = 6;
        assert!(config.validate().is_ok());

        // test invalid ledger format
        config.ledger_format = "invalid".to_string();
        assert!(config.validate().is_err());

        config.ledger_format = "v1".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_merge() {
        let mut base = Config::default();
        let other = Config {
            default_hash: "sha256".to_string(),
            cache_size: 200 * 1024 * 1024,
            compression_level: 9,
            ledger_format: "v1".to_string(),
        };

        base.merge(&other);
        assert_eq!(base.default_hash, "sha256");
        assert_eq!(base.cache_size, 200 * 1024 * 1024);
        assert_eq!(base.compression_level, 9);
        assert_eq!(base.ledger_format, "v1");
    }

    #[test]
    fn test_config_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let original = Config {
            default_hash: "sha256".to_string(),
            cache_size: 50 * 1024 * 1024,
            compression_level: 3,
            ledger_format: "v1".to_string(),
        };

        original.save_to_file(&config_path).unwrap();
        assert!(config_path.exists());

        let loaded = Config::load_from_file(&config_path).unwrap();
        assert_eq!(original, loaded);
    }

    #[test]
    fn test_config_hierarchy() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();

        // create project config
        let project_config_dir = project_dir.join(".sylva");
        std::fs::create_dir_all(&project_config_dir).unwrap();

        let project_config = Config {
            default_hash: "sha256".to_string(),
            cache_size: 200 * 1024 * 1024,
            compression_level: 9,
            ledger_format: "v1".to_string(),
        };

        let project_config_path = ConfigManager::project_config_path(&project_dir);
        project_config.save_to_file(&project_config_path).unwrap();

        // load config for project
        let manager = ConfigManager::for_project(&project_dir).unwrap();

        // should use project config values
        assert_eq!(manager.config.default_hash, "sha256");
        assert_eq!(manager.config.cache_size, 200 * 1024 * 1024);
        assert_eq!(manager.config.compression_level, 9);

        // sources should include at least default and project
        assert!(manager.sources.contains(&ConfigSource::Default));
        assert!(manager.sources.contains(&ConfigSource::Project));
    }

    #[test]
    fn test_project_root_finding() {
        let temp_dir = TempDir::new().unwrap();
        let project_root = temp_dir.path().join("project");
        let nested_dir = project_root.join("src").join("deep");
        std::fs::create_dir_all(&nested_dir).unwrap();

        // create .sylva directory in project root
        let sylva_dir = project_root.join(".sylva");
        std::fs::create_dir_all(&sylva_dir).unwrap();

        // change to nested directory
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&nested_dir).unwrap();

        // should find project root
        let found_root = ConfigManager::find_project_root();

        // restore original directory
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(found_root, Some(project_root));
    }

    #[test]
    fn test_config_sources() {
        let manager = ConfigManager::new().unwrap();
        let (config, sources) = manager.get_config_with_source();

        assert!(!sources.is_empty());
        assert!(sources.contains(&ConfigSource::Default));
        assert_eq!(config.default_hash, "blake3"); // default value
    }
}

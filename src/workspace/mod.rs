use crate::config::Config;
use crate::error::{Result, SylvaError};
use std::fs;
use std::path::{Path, PathBuf};

const SYLVA_DIR: &str = ".sylva";
const LEDGERS_DIR: &str = "ledgers";
const PROOFS_DIR: &str = "proofs";
const SNAPSHOTS_DIR: &str = "snapshots";

#[derive(Debug, Clone)]
pub struct Workspace {
    root_path: PathBuf,
    sylva_path: PathBuf,
    config: Config,
}

impl Workspace {
    /// Create a new workspace instance at the given path
    pub fn new(path: &Path) -> Result<Self> {
        let root_path = path.to_path_buf();
        let sylva_path = root_path.join(SYLVA_DIR);

        if !sylva_path.exists() {
            return Err(SylvaError::WorkspaceError {
                message: format!("No Sylva workspace found at {}", path.display()),
            });
        }

        let config = Config::load()?;

        Ok(Self {
            root_path,
            sylva_path,
            config,
        })
    }

    /// Initialize a new workspace at the given path (alias for initialize)
    pub fn init(path: &Path) -> Result<Self> {
        Self::initialize(path)
    }

    /// Initialize a new workspace at the given path
    pub fn initialize(path: &Path) -> Result<Self> {
        let root_path = path.to_path_buf();
        let sylva_path = root_path.join(SYLVA_DIR);

        if sylva_path.exists() {
            return Err(SylvaError::WorkspaceError {
                message: format!("Sylva workspace already exists at {}", path.display()),
            });
        }

        // Create the .sylva directory structure
        fs::create_dir_all(&sylva_path)?;
        fs::create_dir_all(sylva_path.join(LEDGERS_DIR))?;
        fs::create_dir_all(sylva_path.join(PROOFS_DIR))?;
        fs::create_dir_all(sylva_path.join(SNAPSHOTS_DIR))?;

        // Create and save initial project config
        let config = Config::default();
        config.save_project()?;

        Ok(Self {
            root_path,
            sylva_path,
            config,
        })
    }

    /// Find the workspace root by searching current directory and parent directories
    pub fn find_workspace() -> Result<Self> {
        let current_dir = std::env::current_dir().map_err(|e| SylvaError::WorkspaceError {
            message: format!("Failed to get current directory: {}", e),
        })?;

        Self::find_workspace_in_path(&current_dir)
    }

    /// Find workspace starting from a specific path
    pub fn find_workspace_in_path(start_path: &Path) -> Result<Self> {
        let mut current_path = start_path.to_path_buf();

        loop {
            let sylva_path = current_path.join(SYLVA_DIR);
            if sylva_path.exists() && sylva_path.is_dir() {
                return Self::new(&current_path);
            }

            match current_path.parent() {
                Some(parent) => current_path = parent.to_path_buf(),
                None => break,
            }
        }

        Err(SylvaError::WorkspaceError {
            message: format!(
                "No Sylva workspace found in {} or any parent directory",
                start_path.display()
            ),
        })
    }

    /// Check if a workspace exists at the given path
    pub fn exists_at(path: &Path) -> bool {
        path.join(SYLVA_DIR).exists()
    }

    /// Get the root path of the workspace
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Get the .sylva directory path
    pub fn sylva_path(&self) -> &Path {
        &self.sylva_path
    }

    /// Get the ledgers directory path
    pub fn ledgers_path(&self) -> PathBuf {
        self.sylva_path.join(LEDGERS_DIR)
    }

    /// Get the ledgers directory path (alias for ledgers_path)
    pub fn ledgers_dir(&self) -> PathBuf {
        self.ledgers_path()
    }

    /// Get the proofs directory path
    pub fn proofs_path(&self) -> PathBuf {
        self.sylva_path.join(PROOFS_DIR)
    }

    /// Get the snapshots directory path
    pub fn snapshots_path(&self) -> PathBuf {
        self.sylva_path.join(SNAPSHOTS_DIR)
    }

    /// Get the current workspace configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Update the workspace configuration
    pub fn update_config(&mut self, config: Config) -> Result<()> {
        config.validate()?;
        config.save_project()?;
        self.config = config;
        Ok(())
    }

    /// Get a configuration value by key
    pub fn get_config_value(&self, key: &str) -> Result<String> {
        match key {
            "default_hash" => Ok(self.config.get_default_hash()),
            "cache_size" => Ok(self.config.get_cache_size().to_string()),
            "compression_level" => Ok(self.config.get_compression_level().to_string()),
            "ledger_format" => Ok(self.config.get_ledger_format()),
            _ => Err(SylvaError::ConfigError {
                message: format!("Unknown configuration key: {}", key),
            }),
        }
    }

    /// Set a configuration value by key
    pub fn set_config_value(&mut self, key: &str, value: &str) -> Result<()> {
        let mut new_config = self.config.clone();

        match key {
            "default_hash" => {
                new_config.default_hash = Some(value.to_string());
            }
            "cache_size" => {
                let size = value
                    .parse::<usize>()
                    .map_err(|_| SylvaError::ConfigError {
                        message: format!("Invalid cache_size value: {}", value),
                    })?;
                new_config.cache_size = Some(size);
            }
            "compression_level" => {
                let level = value.parse::<i32>().map_err(|_| SylvaError::ConfigError {
                    message: format!("Invalid compression_level value: {}", value),
                })?;
                new_config.compression_level = Some(level);
            }
            "ledger_format" => {
                new_config.ledger_format = Some(value.to_string());
            }
            _ => {
                return Err(SylvaError::ConfigError {
                    message: format!("Unknown configuration key: {}", key),
                });
            }
        }

        self.update_config(new_config)
    }

    /// Get workspace status information
    pub fn status(&self) -> WorkspaceStatus {
        WorkspaceStatus {
            root_path: self.root_path.clone(),
            sylva_path: self.sylva_path.clone(),
            ledgers_count: self.count_files_in_dir(&self.ledgers_path()),
            proofs_count: self.count_files_in_dir(&self.proofs_path()),
            snapshots_count: self.count_files_in_dir(&self.snapshots_path()),
            config: self.config.clone(),
        }
    }

    /// Count files in a directory
    fn count_files_in_dir(&self, path: &Path) -> usize {
        if let Ok(entries) = fs::read_dir(path) {
            entries.count()
        } else {
            0
        }
    }

    /// Validate workspace integrity
    pub fn validate(&self) -> Result<()> {
        // Check that all required directories exist
        let required_dirs = [
            &self.sylva_path,
            &self.ledgers_path(),
            &self.proofs_path(),
            &self.snapshots_path(),
        ];

        for dir in &required_dirs {
            if !dir.exists() {
                return Err(SylvaError::WorkspaceError {
                    message: format!("Required directory missing: {}", dir.display()),
                });
            }
        }

        // Validate configuration
        self.config.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceStatus {
    pub root_path: PathBuf,
    pub sylva_path: PathBuf,
    pub ledgers_count: usize,
    pub proofs_count: usize,
    pub snapshots_count: usize,
    pub config: Config,
}

impl WorkspaceStatus {
    pub fn display(&self) -> String {
        format!(
            "Workspace Status:\n\
            Root: {}\n\
            Sylva Dir: {}\n\
            Ledgers: {}\n\
            Proofs: {}\n\
            Snapshots: {}\n\
            Config:\n\
            - Default Hash: {}\n\
            - Cache Size: {}\n\
            - Compression Level: {}\n\
            - Ledger Format: {}",
            self.root_path.display(),
            self.sylva_path.display(),
            self.ledgers_count,
            self.proofs_count,
            self.snapshots_count,
            self.config.get_default_hash(),
            self.config.get_cache_size(),
            self.config.get_compression_level(),
            self.config.get_ledger_format(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_workspace_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        let workspace = Workspace::initialize(workspace_path).unwrap();

        assert_eq!(workspace.root_path(), workspace_path);
        assert!(workspace.sylva_path().exists());
        assert!(workspace.ledgers_path().exists());
        assert!(workspace.proofs_path().exists());
        assert!(workspace.snapshots_path().exists());
    }

    #[test]
    fn test_workspace_double_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        Workspace::initialize(workspace_path).unwrap();
        let result = Workspace::initialize(workspace_path);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_workspace_creation_from_existing() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        Workspace::initialize(workspace_path).unwrap();
        let workspace = Workspace::new(workspace_path).unwrap();

        assert_eq!(workspace.root_path(), workspace_path);
    }

    #[test]
    fn test_workspace_creation_from_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        let result = Workspace::new(workspace_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No Sylva workspace found"));
    }

    #[test]
    fn test_workspace_exists_at() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        assert!(!Workspace::exists_at(workspace_path));
        Workspace::initialize(workspace_path).unwrap();
        assert!(Workspace::exists_at(workspace_path));
    }

    #[test]
    fn test_workspace_find_in_path() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let sub_dir = workspace_path.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        Workspace::initialize(workspace_path).unwrap();

        let workspace = Workspace::find_workspace_in_path(&sub_dir).unwrap();
        assert_eq!(workspace.root_path(), workspace_path);
    }

    #[test]
    fn test_workspace_find_in_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();

        let result = Workspace::find_workspace_in_path(workspace_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No Sylva workspace found"));
    }

    #[test]
    fn test_workspace_config_get_set() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let mut workspace = Workspace::initialize(workspace_path).unwrap();

        // Test getting default values
        assert_eq!(
            workspace.get_config_value("default_hash").unwrap(),
            "blake3"
        );
        assert_eq!(workspace.get_config_value("cache_size").unwrap(), "1000");

        // Test setting values
        workspace
            .set_config_value("default_hash", "sha256")
            .unwrap();
        workspace.set_config_value("cache_size", "2000").unwrap();

        assert_eq!(
            workspace.get_config_value("default_hash").unwrap(),
            "sha256"
        );
        assert_eq!(workspace.get_config_value("cache_size").unwrap(), "2000");
    }

    #[test]
    fn test_workspace_config_invalid_key() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let mut workspace = Workspace::initialize(workspace_path).unwrap();

        let result = workspace.get_config_value("invalid_key");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown configuration key"));

        let result = workspace.set_config_value("invalid_key", "value");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown configuration key"));
    }

    #[test]
    fn test_workspace_config_invalid_value() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let mut workspace = Workspace::initialize(workspace_path).unwrap();

        let result = workspace.set_config_value("cache_size", "invalid");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid cache_size value"));
    }

    #[test]
    fn test_workspace_validation() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let workspace = Workspace::initialize(workspace_path).unwrap();

        // Should validate successfully
        workspace.validate().unwrap();

        // Remove a required directory and test validation failure
        fs::remove_dir_all(workspace.ledgers_path()).unwrap();
        let result = workspace.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Required directory missing"));
    }

    #[test]
    fn test_workspace_status() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path();
        let workspace = Workspace::initialize(workspace_path).unwrap();

        let status = workspace.status();
        assert_eq!(status.root_path, workspace_path);
        assert_eq!(status.ledgers_count, 0);
        assert_eq!(status.proofs_count, 0);
        assert_eq!(status.snapshots_count, 0);

        // Create some test files
        fs::write(workspace.ledgers_path().join("test.ledger"), "test").unwrap();
        fs::write(workspace.proofs_path().join("test.proof"), "test").unwrap();

        let status = workspace.status();
        assert_eq!(status.ledgers_count, 1);
        assert_eq!(status.proofs_count, 1);
        assert_eq!(status.snapshots_count, 0);
    }
}

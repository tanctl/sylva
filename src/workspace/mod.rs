//! workspace management for sylva versioned ledger repositories

mod legacy;

use crate::config::{Config, ConfigManager};
use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

// re-export legacy workspace for backward compatibility
pub use legacy::{Workspace as LegacyWorkspace, WorkspaceMetadata, WorkspaceStatus};

/// sylva workspace for versioned ledger repositories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// unique workspace identifier
    pub id: Uuid,
    /// workspace name
    pub name: String,
    /// workspace root directory
    pub root: PathBuf,
    /// when workspace was created
    pub created_at: u64,
    /// when workspace was last modified
    pub modified_at: u64,
    /// workspace description
    pub description: Option<String>,
    /// workspace tags
    pub tags: Vec<String>,
    /// extra properties
    pub properties: HashMap<String, String>,
}

/// workspace initialization options
#[derive(Debug, Clone, Default)]
pub struct WorkspaceInitOptions {
    /// workspace name (defaults to directory name)
    pub name: Option<String>,
    /// workspace description
    pub description: Option<String>,
    /// initial configuration
    pub config: Option<Config>,
    /// create example files
    pub with_examples: bool,
}

/// workspace directory structure
pub struct WorkspaceStructure {
    /// workspace root directory
    pub root: PathBuf,
    /// .sylva directory
    pub sylva_dir: PathBuf,
    /// ledgers directory
    pub ledgers_dir: PathBuf,
    /// proofs directory
    pub proofs_dir: PathBuf,
    /// snapshots directory
    pub snapshots_dir: PathBuf,
    /// config file
    pub config_file: PathBuf,
    /// workspace metadata file
    pub metadata_file: PathBuf,
}

impl WorkspaceStructure {
    /// create workspace structure for given root
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        let root = root.as_ref().to_path_buf();
        let sylva_dir = root.join(".sylva");

        Self {
            root: root.clone(),
            sylva_dir: sylva_dir.clone(),
            ledgers_dir: sylva_dir.join("ledgers"),
            proofs_dir: sylva_dir.join("proofs"),
            snapshots_dir: sylva_dir.join("snapshots"),
            config_file: sylva_dir.join("config.toml"),
            metadata_file: sylva_dir.join("workspace.json"),
        }
    }

    /// check if workspace structure exists
    pub fn exists(&self) -> bool {
        self.sylva_dir.exists() && self.metadata_file.exists()
    }

    /// create all directories in the structure
    pub fn create_directories(&self) -> Result<()> {
        std::fs::create_dir_all(&self.sylva_dir)?;
        std::fs::create_dir_all(&self.ledgers_dir)?;
        std::fs::create_dir_all(&self.proofs_dir)?;
        std::fs::create_dir_all(&self.snapshots_dir)?;
        Ok(())
    }

    /// validate workspace structure integrity
    pub fn validate(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        if !self.sylva_dir.exists() {
            issues.push("Missing .sylva directory".to_string());
        }
        if !self.ledgers_dir.exists() {
            issues.push("Missing ledgers directory".to_string());
        }
        if !self.proofs_dir.exists() {
            issues.push("Missing proofs directory".to_string());
        }
        if !self.snapshots_dir.exists() {
            issues.push("Missing snapshots directory".to_string());
        }
        if !self.metadata_file.exists() {
            issues.push("Missing workspace metadata file".to_string());
        }

        Ok(issues)
    }
}

impl Workspace {
    /// initialize new workspace in given directory
    pub fn init<P: AsRef<Path>>(path: P, options: WorkspaceInitOptions) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let structure = WorkspaceStructure::new(&root);

        // check if workspace already exists
        if structure.exists() {
            return Err(SylvaError::already_exists(format!(
                "Workspace already exists at {}",
                root.display()
            )));
        }

        // create directory structure
        structure.create_directories()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // determine workspace name
        let name = options.name.unwrap_or_else(|| {
            root.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("workspace")
                .to_string()
        });

        let workspace = Self {
            id: Uuid::new_v4(),
            name,
            root: root.clone(),
            created_at: now,
            modified_at: now,
            description: options.description,
            tags: Vec::new(),
            properties: HashMap::new(),
        };

        // save workspace metadata
        workspace.save_metadata(&structure.metadata_file)?;

        // create or save configuration
        let config = options.config.unwrap_or_default();
        config.save_to_file(&structure.config_file)?;

        // create example files if requested
        if options.with_examples {
            workspace.create_examples(&structure)?;
        }

        Ok(workspace)
    }

    /// load workspace from directory
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let root = Self::find_workspace_root(path)?;
        let structure = WorkspaceStructure::new(&root);

        if !structure.exists() {
            return Err(SylvaError::not_found(format!(
                "No workspace found at {}",
                root.display()
            )));
        }

        let content = std::fs::read_to_string(&structure.metadata_file)?;
        let workspace: Workspace = serde_json::from_str(&content)?;

        Ok(workspace)
    }

    /// find workspace root by looking for .sylva directory
    pub fn find_workspace_root<P: AsRef<Path>>(start_path: P) -> Result<PathBuf> {
        let mut current = start_path.as_ref().to_path_buf();

        // make path absolute
        if current.is_relative() {
            current = std::env::current_dir()?.join(current);
        }

        loop {
            let sylva_dir = current.join(".sylva");
            if sylva_dir.exists() && sylva_dir.is_dir() {
                return Ok(current);
            }

            if !current.pop() {
                break;
            }
        }

        Err(SylvaError::not_found(
            "No workspace found (no .sylva directory in current or parent directories)".to_string(),
        ))
    }

    /// check if we're inside a workspace
    pub fn is_inside_workspace() -> bool {
        Self::find_workspace_root(".").is_ok()
    }

    /// get workspace structure
    pub fn structure(&self) -> WorkspaceStructure {
        WorkspaceStructure::new(&self.root)
    }

    /// save workspace metadata
    pub fn save_metadata(&self, metadata_file: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(metadata_file, content)?;
        Ok(())
    }

    /// update modification time
    pub fn touch(&mut self) -> Result<()> {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let structure = self.structure();
        self.save_metadata(&structure.metadata_file)
    }

    /// add tag to workspace
    pub fn add_tag(&mut self, tag: String) -> Result<()> {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.touch()?;
        }
        Ok(())
    }

    /// remove tag from workspace
    pub fn remove_tag(&mut self, tag: &str) -> Result<()> {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.touch()?;
        }
        Ok(())
    }

    /// set workspace description
    pub fn set_description(&mut self, description: String) -> Result<()> {
        self.description = Some(description);
        self.touch()
    }

    /// set workspace property
    pub fn set_property(&mut self, key: String, value: String) -> Result<()> {
        self.properties.insert(key, value);
        self.touch()
    }

    /// get workspace property
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }

    /// remove workspace property
    pub fn remove_property(&mut self, key: &str) -> Result<()> {
        if self.properties.remove(key).is_some() {
            self.touch()?;
        }
        Ok(())
    }

    /// validate workspace integrity
    pub fn validate(&self) -> Result<Vec<String>> {
        let structure = self.structure();
        structure.validate()
    }

    /// get workspace status
    pub fn status(&self) -> Result<WorkspaceInfo> {
        let structure = self.structure();
        let issues = self.validate()?;

        // count ledgers
        let ledger_count = if structure.ledgers_dir.exists() {
            std::fs::read_dir(&structure.ledgers_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .count()
        } else {
            0
        };

        // count proofs
        let proof_count = if structure.proofs_dir.exists() {
            std::fs::read_dir(&structure.proofs_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .count()
        } else {
            0
        };

        // count snapshots
        let snapshot_count = if structure.snapshots_dir.exists() {
            std::fs::read_dir(&structure.snapshots_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .count()
        } else {
            0
        };

        Ok(WorkspaceInfo {
            id: self.id,
            name: self.name.clone(),
            root: self.root.clone(),
            created_at: self.created_at,
            modified_at: self.modified_at,
            description: self.description.clone(),
            tags: self.tags.clone(),
            ledger_count,
            proof_count,
            snapshot_count,
            has_config: structure.config_file.exists(),
            issues,
        })
    }

    /// create example files for new workspace
    fn create_examples(&self, _structure: &WorkspaceStructure) -> Result<()> {
        // create example README
        let readme_content = format!(
            r#"# {}

This is a Sylva workspace for versioned ledger management.

## Structure

- `.sylva/` - Workspace configuration and metadata
- `.sylva/ledgers/` - Ledger data files
- `.sylva/proofs/` - Cryptographic proofs
- `.sylva/snapshots/` - Workspace snapshots

## Getting Started

1. Add entries to the ledger:
   ```
   sylva add "my first entry"
   ```

2. Generate proofs:
   ```
   sylva proof <entry-id>
   ```

3. View workspace status:
   ```
   sylva status
   ```

For more commands, run: `sylva --help`
"#,
            self.name
        );

        std::fs::write(self.root.join("README.md"), readme_content)?;

        // create example .gitignore
        let gitignore_content = r#"# Sylva workspace files
.sylva/ledgers/*.tmp
.sylva/proofs/*.tmp
.sylva/snapshots/*.tmp

# OS files
.DS_Store
Thumbs.db

# Editor files
*.swp
*.swo
*~
"#;

        std::fs::write(self.root.join(".gitignore"), gitignore_content)?;

        Ok(())
    }
}

/// workspace information and status
#[derive(Debug, Clone)]
pub struct WorkspaceInfo {
    /// workspace id
    pub id: Uuid,
    /// workspace name
    pub name: String,
    /// workspace root path
    pub root: PathBuf,
    /// creation timestamp
    pub created_at: u64,
    /// modification timestamp
    pub modified_at: u64,
    /// workspace description
    pub description: Option<String>,
    /// workspace tags
    pub tags: Vec<String>,
    /// number of ledgers
    pub ledger_count: usize,
    /// number of proofs
    pub proof_count: usize,
    /// number of snapshots
    pub snapshot_count: usize,
    /// whether config file exists
    pub has_config: bool,
    /// validation issues
    pub issues: Vec<String>,
}

/// workspace manager for operations
pub struct WorkspaceManager {
    workspace: Option<Workspace>,
    config_manager: Option<ConfigManager>,
}

impl WorkspaceManager {
    /// create new workspace manager
    pub fn new() -> Self {
        Self {
            workspace: None,
            config_manager: None,
        }
    }

    /// ensure we're in a workspace
    pub fn require_workspace(&mut self) -> Result<&mut Workspace> {
        if self.workspace.is_none() {
            let workspace = Workspace::load(".")?;
            self.workspace = Some(workspace);
        }

        self.workspace.as_mut().ok_or_else(|| {
            SylvaError::workspace_error(
                "Not in a workspace. Use 'sylva init' to create one or navigate to an existing workspace."
            )
        })
    }

    /// get config manager for current workspace
    pub fn config_manager(&mut self) -> Result<&mut ConfigManager> {
        if self.config_manager.is_none() {
            let workspace = self.require_workspace()?;
            let config_manager = ConfigManager::for_project(&workspace.root)?;
            self.config_manager = Some(config_manager);
        }

        self.config_manager.as_mut().ok_or_else(|| {
            SylvaError::config_error("Failed to initialize config manager".to_string())
        })
    }

    /// initialize workspace
    pub fn init<P: AsRef<Path>>(&mut self, path: P, options: WorkspaceInitOptions) -> Result<()> {
        let workspace = Workspace::init(path, options)?;
        self.workspace = Some(workspace);
        self.config_manager = None; // reset config manager
        Ok(())
    }

    /// get workspace status
    pub fn status(&mut self) -> Result<WorkspaceInfo> {
        let workspace = self.require_workspace()?;
        workspace.status()
    }

    /// get configuration value
    pub fn get_config(&mut self, key: &str) -> Result<String> {
        let config_manager = self.config_manager()?;
        let config = &config_manager.config;

        match key {
            "default_hash" => Ok(config.default_hash.clone()),
            "cache_size" => Ok(config.cache_size.to_string()),
            "compression_level" => Ok(config.compression_level.to_string()),
            "ledger_format" => Ok(config.ledger_format.clone()),
            _ => Err(SylvaError::config_error(format!(
                "Unknown configuration key: {}",
                key
            ))),
        }
    }

    /// set configuration value
    pub fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        // get workspace root first
        let workspace_root = {
            let workspace = self.require_workspace()?;
            workspace.root.clone()
        };

        // now work with config manager
        let config_manager = self.config_manager()?;
        let config = &mut config_manager.config;

        match key {
            "default_hash" => {
                let valid_hashes = ["blake3", "sha256", "keccak256"];
                if !valid_hashes.contains(&value) {
                    return Err(SylvaError::config_error(format!(
                        "Invalid hash algorithm '{}'. Valid options: {}",
                        value,
                        valid_hashes.join(", ")
                    )));
                }
                config.default_hash = value.to_string();
            }
            "cache_size" => {
                let size: u64 = value.parse().map_err(|_| {
                    SylvaError::config_error("Cache size must be a number".to_string())
                })?;
                config.cache_size = size;
            }
            "compression_level" => {
                let level: u8 = value.parse().map_err(|_| {
                    SylvaError::config_error("Compression level must be a number 0-9".to_string())
                })?;
                if level > 9 {
                    return Err(SylvaError::config_error(
                        "Compression level must be 0-9".to_string(),
                    ));
                }
                config.compression_level = level;
            }
            "ledger_format" => {
                if value != "v1" {
                    return Err(SylvaError::config_error(
                        "Only ledger format 'v1' is currently supported".to_string(),
                    ));
                }
                config.ledger_format = value.to_string();
            }
            _ => {
                return Err(SylvaError::config_error(format!(
                    "Unknown configuration key: {}",
                    key
                )));
            }
        }

        // validate and save
        config.validate()?;
        config_manager.save_project_config(Some(&workspace_root))?;

        Ok(())
    }

    /// list all configuration values
    pub fn list_config(&mut self) -> Result<HashMap<String, String>> {
        let config_manager = self.config_manager()?;
        let config = &config_manager.config;

        let mut values = HashMap::new();
        values.insert("default_hash".to_string(), config.default_hash.clone());
        values.insert("cache_size".to_string(), config.cache_size.to_string());
        values.insert(
            "compression_level".to_string(),
            config.compression_level.to_string(),
        );
        values.insert("ledger_format".to_string(), config.ledger_format.clone());

        Ok(values)
    }
}

impl Default for WorkspaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_workspace_init() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let options = WorkspaceInitOptions {
            name: Some("test".to_string()),
            description: Some("Test workspace".to_string()),
            config: None,
            with_examples: true,
        };

        let workspace = Workspace::init(&workspace_path, options).unwrap();

        assert_eq!(workspace.name, "test");
        assert_eq!(workspace.description, Some("Test workspace".to_string()));
        assert_eq!(workspace.root, workspace_path);

        let structure = workspace.structure();
        assert!(structure.sylva_dir.exists());
        assert!(structure.ledgers_dir.exists());
        assert!(structure.proofs_dir.exists());
        assert!(structure.snapshots_dir.exists());
        assert!(structure.config_file.exists());
        assert!(structure.metadata_file.exists());

        // check example files
        assert!(workspace_path.join("README.md").exists());
        assert!(workspace_path.join(".gitignore").exists());
    }

    #[test]
    fn test_workspace_init_duplicate() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let options = WorkspaceInitOptions::default();
        Workspace::init(&workspace_path, options.clone()).unwrap();

        // second init should fail
        let result = Workspace::init(&workspace_path, options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_workspace_load() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let options = WorkspaceInitOptions {
            name: Some("test".to_string()),
            description: Some("Test workspace".to_string()),
            config: None,
            with_examples: false,
        };

        let original = Workspace::init(&workspace_path, options).unwrap();
        let loaded = Workspace::load(&workspace_path).unwrap();

        assert_eq!(original.id, loaded.id);
        assert_eq!(original.name, loaded.name);
        assert_eq!(original.description, loaded.description);
        assert_eq!(original.root, loaded.root);
    }

    #[test]
    fn test_workspace_find_root() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("workspace");
        let nested_path = workspace_path.join("src").join("deep");

        // create workspace
        let options = WorkspaceInitOptions::default();
        Workspace::init(&workspace_path, options).unwrap();

        // create nested directory
        std::fs::create_dir_all(&nested_path).unwrap();

        // should find workspace root from nested directory
        let found_root = Workspace::find_workspace_root(&nested_path).unwrap();
        assert_eq!(found_root, workspace_path);
    }

    #[test]
    fn test_workspace_find_root_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let non_workspace_path = temp_dir.path().join("not_a_workspace");
        std::fs::create_dir_all(&non_workspace_path).unwrap();

        let result = Workspace::find_workspace_root(&non_workspace_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No workspace found"));
    }

    #[test]
    fn test_workspace_structure_validation() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let options = WorkspaceInitOptions::default();
        let workspace = Workspace::init(&workspace_path, options).unwrap();

        let issues = workspace.validate().unwrap();
        assert!(issues.is_empty());

        // remove a directory and check validation
        let structure = workspace.structure();
        std::fs::remove_dir(&structure.proofs_dir).unwrap();

        let issues = workspace.validate().unwrap();
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|issue| issue.contains("proofs")));
    }

    #[test]
    fn test_workspace_manager_init() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut manager = WorkspaceManager::new();
        let options = WorkspaceInitOptions {
            name: Some("test".to_string()),
            description: None,
            config: None,
            with_examples: false,
        };

        manager.init(&workspace_path, options).unwrap();

        let status = manager.status().unwrap();
        assert_eq!(status.name, "test");
        assert_eq!(status.root, workspace_path);
    }

    #[test]
    fn test_workspace_manager_config() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut manager = WorkspaceManager::new();
        let options = WorkspaceInitOptions::default();
        manager.init(&workspace_path, options).unwrap();

        // test get config
        let hash_value = manager.get_config("default_hash").unwrap();
        assert_eq!(hash_value, "blake3");

        // test set config
        manager.set_config("default_hash", "sha256").unwrap();
        let new_hash_value = manager.get_config("default_hash").unwrap();
        assert_eq!(new_hash_value, "sha256");

        // test invalid config
        let result = manager.set_config("default_hash", "invalid");
        assert!(result.is_err());

        // test list config
        let config_values = manager.list_config().unwrap();
        assert!(config_values.contains_key("default_hash"));
        assert!(config_values.contains_key("cache_size"));
        assert_eq!(config_values["default_hash"], "sha256");
    }

    #[test]
    fn test_workspace_manager_require_workspace() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let non_workspace_dir = temp_dir.path().join("not_a_workspace");
        std::fs::create_dir_all(&non_workspace_dir).unwrap();

        // change to non-workspace directory
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&non_workspace_dir).unwrap();

        let mut manager = WorkspaceManager::new();

        // should fail when not in workspace
        let result = manager.require_workspace();
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("No workspace found") || error_msg.contains("Not in a workspace")
        );

        // restore original directory
        std::env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_workspace_operations() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let options = WorkspaceInitOptions::default();
        let mut workspace = Workspace::init(&workspace_path, options).unwrap();

        // test tags
        workspace.add_tag("important".to_string()).unwrap();
        assert!(workspace.tags.contains(&"important".to_string()));

        workspace.remove_tag("important").unwrap();
        assert!(!workspace.tags.contains(&"important".to_string()));

        // test description
        workspace
            .set_description("New description".to_string())
            .unwrap();
        assert_eq!(workspace.description, Some("New description".to_string()));

        // test properties
        workspace
            .set_property("key1".to_string(), "value1".to_string())
            .unwrap();
        assert_eq!(workspace.get_property("key1"), Some(&"value1".to_string()));

        workspace.remove_property("key1").unwrap();
        assert_eq!(workspace.get_property("key1"), None);
    }
}

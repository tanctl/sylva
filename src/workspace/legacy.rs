//! workspace management for Sylva projects

use crate::config::LegacyConfig;
use crate::error::{Result, SylvaError};
use crate::ledger::Ledger;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
/// sylva project workspace
pub struct Workspace {
    /// unique workspace identifier
    pub id: Uuid,
    /// workspace name
    pub name: String,
    /// workspace directory path
    pub path: PathBuf,
    #[serde(skip)]
    /// optional ledger instance
    pub ledger: Option<Ledger>,
    /// workspace metadata
    pub metadata: WorkspaceMetadata,
    /// workspace configuration
    pub config: LegacyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// metadata for workspaces
pub struct WorkspaceMetadata {
    /// when workspace was created
    pub created_at: u64,
    /// when workspace was last modified
    pub modified_at: u64,
    /// optional description
    pub description: Option<String>,
    /// workspace tags
    pub tags: Vec<String>,
    /// extra properties
    pub properties: std::collections::HashMap<String, String>,
}

impl Workspace {
    /// create new workspace
    pub fn new(name: String, path: PathBuf) -> Result<Self> {
        let id = Uuid::new_v4();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let workspace = Self {
            id,
            name,
            path,
            ledger: None,
            metadata: WorkspaceMetadata {
                created_at: now,
                modified_at: now,
                description: None,
                tags: Vec::new(),
                properties: std::collections::HashMap::new(),
            },
            config: LegacyConfig::default(),
        };

        Ok(workspace)
    }

    /// initialize workspace directory and files
    pub fn initialize(&mut self) -> Result<()> {
        std::fs::create_dir_all(&self.path)?;

        let data_dir = self.path.join("data");
        let config_dir = self.path.join("config");
        let temp_dir = self.path.join("temp");

        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(&config_dir)?;
        std::fs::create_dir_all(&temp_dir)?;

        self.save_metadata()?;
        let config_path = config_dir.join("sylva.toml");
        self.config.save_to_file(&config_path)?;

        self.ledger = Some(Ledger::new(data_dir)?);

        Ok(())
    }

    /// load existing workspace from directory
    pub fn load(path: PathBuf) -> Result<Self> {
        let metadata_path = path.join("workspace.json");
        if !metadata_path.exists() {
            return Err(SylvaError::workspace_error(
                "Workspace metadata not found. Use 'sylva init' to create a new workspace.",
            ));
        }

        let content = std::fs::read_to_string(&metadata_path)?;
        let mut workspace: Workspace = serde_json::from_str(&content)?;

        let config_path = path.join("config").join("sylva.toml");
        if config_path.exists() {
            workspace.config = LegacyConfig::load_from_file(&config_path)?;
        }

        let data_dir = path.join("data");
        if data_dir.exists() {
            workspace.ledger = Some(Ledger::load(data_dir)?);
        }

        Ok(workspace)
    }

    /// save workspace metadata to disk
    pub fn save_metadata(&mut self) -> Result<()> {
        self.metadata.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata_path = self.path.join("workspace.json");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(metadata_path, content)?;

        Ok(())
    }

    /// get workspace status info
    pub fn status(&self) -> Result<WorkspaceStatus> {
        let mut status = WorkspaceStatus {
            name: self.name.clone(),
            path: self.path.clone(),
            initialized: false,
            ledger_entries: 0,
            total_size: 0,
            last_activity: self.metadata.modified_at,
        };

        status.initialized = self.path.join("workspace.json").exists();

        if let Some(ref ledger) = self.ledger {
            if let Ok(stats) = ledger.stats() {
                status.ledger_entries = stats.entry_count;
                status.total_size = stats.total_size;
            }
        }

        Ok(status)
    }

    /// cleanup temporary files
    pub fn cleanup(&self) -> Result<()> {
        let temp_dir = self.path.join("temp");
        if temp_dir.exists() {
            std::fs::remove_dir_all(&temp_dir)?;
            std::fs::create_dir(&temp_dir)?;
        }
        Ok(())
    }

    /// add tag to workspace
    pub fn add_tag(&mut self, tag: String) -> Result<()> {
        if !self.metadata.tags.contains(&tag) {
            self.metadata.tags.push(tag);
            self.save_metadata()?;
        }
        Ok(())
    }

    /// remove tag from workspace
    pub fn remove_tag(&mut self, tag: &str) -> Result<()> {
        self.metadata.tags.retain(|t| t != tag);
        self.save_metadata()?;
        Ok(())
    }

    /// set workspace description
    pub fn set_description(&mut self, description: String) -> Result<()> {
        self.metadata.description = Some(description);
        self.save_metadata()?;
        Ok(())
    }

    /// add property to workspace
    pub fn add_property(&mut self, key: String, value: String) -> Result<()> {
        self.metadata.properties.insert(key, value);
        self.save_metadata()?;
        Ok(())
    }

    /// get property from workspace
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.metadata.properties.get(key)
    }

    /// validate workspace integrity
    pub fn validate(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        let required_dirs = ["data", "config", "temp"];
        for dir in &required_dirs {
            let dir_path = self.path.join(dir);
            if !dir_path.exists() {
                issues.push(format!("Missing required directory: {}", dir));
            }
        }

        let metadata_path = self.path.join("workspace.json");
        if !metadata_path.exists() {
            issues.push("Missing workspace metadata file".to_string());
        }

        if let Err(e) = self.config.validate() {
            issues.push(format!("Configuration error: {}", e));
        }

        if let Some(ref ledger) = self.ledger {
            if let Err(e) = ledger.validate() {
                issues.push(format!("Ledger validation error: {}", e));
            }
        }

        Ok(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// workspace status information
pub struct WorkspaceStatus {
    /// workspace name
    pub name: String,
    /// workspace path
    pub path: PathBuf,
    /// whether workspace is initialized
    pub initialized: bool,
    /// number of ledger entries
    pub ledger_entries: usize,
    /// total size in bytes
    pub total_size: u64,
    /// last activity timestamp
    pub last_activity: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_workspace_creation() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let workspace = Workspace::new("test".to_string(), workspace_path.clone()).unwrap();
        assert_eq!(workspace.name, "test");
        assert_eq!(workspace.path, workspace_path);
    }

    #[test]
    fn test_workspace_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut workspace = Workspace::new("test".to_string(), workspace_path.clone()).unwrap();
        workspace.initialize().unwrap();

        assert!(workspace_path.join("data").exists());
        assert!(workspace_path.join("config").exists());
        assert!(workspace_path.join("temp").exists());
        assert!(workspace_path.join("workspace.json").exists());
    }

    #[test]
    fn test_workspace_metadata_operations() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut workspace = Workspace::new("test".to_string(), workspace_path).unwrap();
        workspace.initialize().unwrap();

        workspace.add_tag("important".to_string()).unwrap();
        assert!(workspace.metadata.tags.contains(&"important".to_string()));

        workspace.remove_tag("important").unwrap();
        assert!(!workspace.metadata.tags.contains(&"important".to_string()));

        workspace
            .set_description("Test workspace".to_string())
            .unwrap();
        assert_eq!(
            workspace.metadata.description,
            Some("Test workspace".to_string())
        );

        workspace
            .add_property("key1".to_string(), "value1".to_string())
            .unwrap();
        assert_eq!(workspace.get_property("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_workspace_load_save() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut workspace = Workspace::new("test".to_string(), workspace_path.clone()).unwrap();
        workspace.initialize().unwrap();
        workspace.add_tag("test_tag".to_string()).unwrap();

        let loaded_workspace = Workspace::load(workspace_path).unwrap();
        assert_eq!(loaded_workspace.name, "test");
        assert!(loaded_workspace
            .metadata
            .tags
            .contains(&"test_tag".to_string()));
    }
}

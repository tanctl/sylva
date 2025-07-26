//! cli implementation

use crate::config::Config;
use crate::error::{Result, SylvaError};
use crate::workspace::Workspace;
use std::path::PathBuf;
use uuid::Uuid;

/// handles cli commands and workspace operations
pub struct CliProcessor {
    workspace: Option<Workspace>,
    #[allow(dead_code)]
    config: Config,
    verbose: bool,
}

impl CliProcessor {
    /// create new cli processor with config
    pub fn new(config_path: Option<String>, verbose: bool) -> Result<Self> {
        let config = if let Some(path) = config_path {
            Config::load_from_file(&PathBuf::from(path))?
        } else {
            Config::load_from_env().unwrap_or_default()
        };

        Ok(Self {
            workspace: None,
            config,
            verbose,
        })
    }

    /// initialize new workspace at given path
    pub fn init_workspace(&mut self, path: String) -> Result<()> {
        let workspace_path = PathBuf::from(path);

        if workspace_path.join("workspace.json").exists() {
            return Err(SylvaError::already_exists(format!(
                "Workspace already exists at {}",
                workspace_path.display()
            )));
        }

        let mut workspace = Workspace::new(
            workspace_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            workspace_path,
        )?;

        workspace.initialize()?;
        self.workspace = Some(workspace);

        if self.verbose {
            println!(
                "Initialized Sylva workspace at {}",
                self.workspace.as_ref().unwrap().path.display()
            );
        }

        Ok(())
    }

    /// load existing workspace from path
    pub fn load_workspace(&mut self, path: Option<String>) -> Result<()> {
        let workspace_path = if let Some(p) = path {
            PathBuf::from(p)
        } else {
            std::env::current_dir()?
        };

        self.workspace = Some(Workspace::load(workspace_path)?);
        Ok(())
    }

    /// add new entry to ledger
    pub fn add_entry(&mut self, data: String, message: Option<String>) -> Result<()> {
        let verbose = self.verbose;

        let workspace = self.get_workspace_mut()?;
        let ledger = workspace
            .ledger
            .as_mut()
            .ok_or_else(|| SylvaError::workspace_error("Ledger not initialized"))?;

        let entry_data = if std::path::Path::new(&data).exists() {
            if verbose {
                println!("Reading data from file: {}", data);
            }
            std::fs::read(&data)?
        } else {
            data.into_bytes()
        };

        let entry_id = ledger.add_entry(entry_data, message.clone())?;

        println!("Added entry: {}", entry_id);
        if let Some(msg) = message {
            println!("Message: {}", msg);
        }

        workspace.save_metadata()?;

        Ok(())
    }

    /// verify entry exists and proof is valid
    pub fn verify(&mut self, target: String) -> Result<()> {
        let workspace = self.get_workspace_mut()?;
        let ledger = workspace
            .ledger
            .as_mut()
            .ok_or_else(|| SylvaError::workspace_error("Ledger not initialized"))?;

        if let Ok(uuid) = Uuid::parse_str(&target) {
            if ledger.entry_exists(uuid)? {
                println!("✓ Entry {} exists and is valid", uuid);

                let entry = ledger.get_entry(uuid)?;
                let proof = ledger.generate_proof(uuid)?;
                let is_valid = ledger.verify_proof(&proof, &entry.data)?;

                if is_valid {
                    println!("✓ Proof verification passed");
                } else {
                    println!("✗ Proof verification failed");
                }
            } else {
                println!("✗ Entry {} not found", uuid);
            }
        } else {
            println!("Proof file verification not yet implemented: {}", target);
        }

        Ok(())
    }

    /// list entries in the ledger
    pub fn list_entries(&mut self, detailed: bool, limit: Option<usize>) -> Result<()> {
        let workspace = self.get_workspace_mut()?;
        let ledger = workspace
            .ledger
            .as_mut()
            .ok_or_else(|| SylvaError::workspace_error("Ledger not initialized"))?;

        let mut entry_ids = ledger.list_entries()?;

        if let Some(limit) = limit {
            entry_ids.truncate(limit);
        }

        if entry_ids.is_empty() {
            println!("No entries found");
            return Ok(());
        }

        println!("Entries ({})", entry_ids.len());
        println!();

        for id in entry_ids {
            if detailed {
                let entry = ledger.get_entry(id)?;
                println!("ID: {}", id);
                println!("Version: {}", entry.version);
                println!("Size: {} bytes", entry.data.len());
                println!("Hash: {}", entry.data_hash);
                println!("Timestamp: {}", entry.metadata.timestamp);
                if let Some(ref message) = entry.metadata.message {
                    println!("Message: {}", message);
                }
                if !entry.metadata.tags.is_empty() {
                    println!("Tags: {}", entry.metadata.tags.join(", "));
                }
                println!();
            } else {
                let metadata = ledger.get_entry_metadata(id)?;
                let message = metadata.message.as_deref().unwrap_or("");
                println!("{} - {} bytes - {}", id, metadata.size, message);
            }
        }

        Ok(())
    }

    /// show detailed info for an entry
    pub fn show_entry(&mut self, id_str: String) -> Result<()> {
        let workspace = self.get_workspace_mut()?;
        let ledger = workspace
            .ledger
            .as_mut()
            .ok_or_else(|| SylvaError::workspace_error("Ledger not initialized"))?;

        let id = Uuid::parse_str(&id_str)
            .map_err(|_| SylvaError::invalid_input("Invalid entry ID format"))?;

        let entry = ledger.get_entry(id)?;

        println!("Entry Details");
        println!("=============");
        println!("ID: {}", entry.id);
        println!("Version: {}", entry.version);
        println!("Data Hash: {}", entry.data_hash);
        println!("Size: {} bytes", entry.data.len());
        println!("Timestamp: {}", entry.metadata.timestamp);

        if let Some(ref message) = entry.metadata.message {
            println!("Message: {}", message);
        }

        if !entry.metadata.tags.is_empty() {
            println!("Tags: {}", entry.metadata.tags.join(", "));
        }

        if let Some(ref content_type) = entry.metadata.content_type {
            println!("Content Type: {}", content_type);
        }

        if let Some(previous_id) = entry.metadata.previous_id {
            println!("Previous Version: {}", previous_id);
        }

        if !entry.metadata.properties.is_empty() {
            println!("Properties:");
            for (key, value) in &entry.metadata.properties {
                println!("  {}: {}", key, value);
            }
        }

        Ok(())
    }

    /// generate proof for an entry
    pub fn generate_proof(&mut self, id_str: String, output: Option<String>) -> Result<()> {
        let workspace = self.get_workspace_mut()?;
        let ledger = workspace
            .ledger
            .as_mut()
            .ok_or_else(|| SylvaError::workspace_error("Ledger not initialized"))?;

        let id = Uuid::parse_str(&id_str)
            .map_err(|_| SylvaError::invalid_input("Invalid entry ID format"))?;

        let proof = ledger.generate_proof(id)?;
        let proof_json = serde_json::to_string_pretty(&proof)?;

        if let Some(output_path) = output {
            std::fs::write(&output_path, &proof_json)?;
            println!("Proof saved to: {}", output_path);
        } else {
            println!("{}", proof_json);
        }

        Ok(())
    }

    /// show workspace status and info
    pub fn show_status(&mut self) -> Result<()> {
        if let Some(ref workspace) = self.workspace {
            let status = workspace.status()?;

            println!("Workspace Status");
            println!("================");
            println!("Name: {}", status.name);
            println!("Path: {}", status.path.display());
            println!(
                "Initialized: {}",
                if status.initialized { "Yes" } else { "No" }
            );
            println!("Entries: {}", status.ledger_entries);
            println!("Total Size: {} bytes", status.total_size);
            println!("Last Activity: {}", status.last_activity);

            let issues = workspace.validate()?;
            if !issues.is_empty() {
                println!("\nValidation Issues:");
                for issue in issues {
                    println!("  ⚠️  {}", issue);
                }
            }
        } else {
            println!("No workspace loaded. Use 'sylva init' to create one or navigate to an existing workspace.");
        }

        Ok(())
    }

    /// export data in specified format
    pub fn export_data(&mut self, format: String, output: Option<String>) -> Result<()> {
        println!("Export functionality not yet implemented");
        println!("Format: {}", format);
        if let Some(out) = output {
            println!("Output: {}", out);
        }
        Ok(())
    }

    /// import data from file
    pub fn import_data(&mut self, input: String, format: String) -> Result<()> {
        println!("Import functionality not yet implemented");
        println!("Input: {}", input);
        println!("Format: {}", format);
        Ok(())
    }

    fn get_workspace_mut(&mut self) -> Result<&mut Workspace> {
        if self.workspace.is_none() {
            if let Ok(workspace) = Workspace::load(std::env::current_dir()?) {
                self.workspace = Some(workspace);
            }
        }

        self.workspace.as_mut().ok_or_else(|| {
            SylvaError::workspace_error("No workspace found. Use 'sylva init' to create one.")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cli_processor_creation() {
        let processor = CliProcessor::new(None, false).unwrap();
        assert!(processor.workspace.is_none());
    }

    #[test]
    fn test_workspace_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let workspace_path = temp_dir.path().join("test_workspace");

        let mut processor = CliProcessor::new(None, false).unwrap();
        processor
            .init_workspace(workspace_path.to_string_lossy().to_string())
            .unwrap();

        assert!(processor.workspace.is_some());
        assert!(workspace_path.join("workspace.json").exists());
    }
}

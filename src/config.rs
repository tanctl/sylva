//! configuration management for Sylva

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub storage: StorageConfig,
    pub hashing: HashingConfig,
    pub proof: ProofConfig,
    pub workspace: WorkspaceConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub base_path: Option<PathBuf>,
    pub cache_size: Option<u64>,
    pub connection_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Memory,
    Filesystem,
    Database,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashingConfig {
    pub algorithm: HashAlgorithm,
    pub parallel_hashing: bool,
    pub chunk_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    pub default_ttl: u64,
    pub enable_caching: bool,
    pub max_cache_size: usize,
    pub compress_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub default_name: String,
    pub auto_save_interval: u64,
    pub max_size: Option<u64>,
    pub backup: BackupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval: u64,
    pub max_backups: usize,
    pub backup_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub worker_threads: Option<usize>,
    pub memory_pool_size: u64,
    pub enable_mmap: bool,
    pub io_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage: StorageConfig {
                backend: StorageBackend::Filesystem,
                base_path: Some(PathBuf::from("./sylva_data")),
                cache_size: Some(100 * 1024 * 1024),
                connection_string: None,
            },
            hashing: HashingConfig {
                algorithm: HashAlgorithm::Sha256,
                parallel_hashing: true,
                chunk_size: 64 * 1024,
            },
            proof: ProofConfig {
                default_ttl: 86400,
                enable_caching: true,
                max_cache_size: 1000,
                compress_proofs: true,
            },
            workspace: WorkspaceConfig {
                default_name: "default".to_string(),
                auto_save_interval: 300,
                max_size: Some(1024 * 1024 * 1024),
                backup: BackupConfig {
                    enabled: false,
                    interval: 3600,
                    max_backups: 10,
                    backup_dir: None,
                },
            },
            performance: PerformanceConfig {
                worker_threads: None,
                memory_pool_size: 50 * 1024 * 1024,
                enable_mmap: true,
                io_buffer_size: 8 * 1024,
            },
        }
    }
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| SylvaError::config_error(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| SylvaError::config_error(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load_from_env() -> Result<Self> {
        let mut config = Config::default();

        if let Ok(backend) = std::env::var("SYLVA_STORAGE_BACKEND") {
            config.storage.backend = match backend.to_lowercase().as_str() {
                "memory" => StorageBackend::Memory,
                "filesystem" => StorageBackend::Filesystem,
                "database" => StorageBackend::Database,
                _ => {
                    return Err(SylvaError::config_error(format!(
                        "Invalid storage backend: {}",
                        backend
                    )))
                }
            };
        }

        if let Ok(path) = std::env::var("SYLVA_STORAGE_PATH") {
            config.storage.base_path = Some(PathBuf::from(path));
        }

        if let Ok(ttl_str) = std::env::var("SYLVA_PROOF_TTL") {
            config.proof.default_ttl = ttl_str
                .parse()
                .map_err(|_| SylvaError::config_error("Invalid SYLVA_PROOF_TTL value"))?;
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        match self.storage.backend {
            StorageBackend::Filesystem => {
                if self.storage.base_path.is_none() {
                    return Err(SylvaError::config_error(
                        "Filesystem backend requires base_path to be set",
                    ));
                }
            }
            StorageBackend::Database => {
                if self.storage.connection_string.is_none() {
                    return Err(SylvaError::config_error(
                        "Database backend requires connection_string to be set",
                    ));
                }
            }
            StorageBackend::Memory => {
            }
        }

        if let Some(threads) = self.performance.worker_threads {
            if threads == 0 {
                return Err(SylvaError::config_error(
                    "worker_threads must be greater than 0",
                ));
            }
        }

        if self.proof.default_ttl == 0 {
            return Err(SylvaError::config_error(
                "default_ttl must be greater than 0",
            ));
        }

        Ok(())
    }

    pub fn effective_worker_threads(&self) -> usize {
        self.performance.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(matches!(config.storage.backend, StorageBackend::Filesystem));
        assert_eq!(config.hashing.algorithm, HashAlgorithm::Sha256);
        assert_eq!(config.proof.default_ttl, 86400);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = config;
        invalid_config.proof.default_ttl = 0;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_effective_worker_threads() {
        let mut config = Config::default();
        assert!(config.effective_worker_threads() >= 1);

        config.performance.worker_threads = Some(4);
        assert_eq!(config.effective_worker_threads(), 4);
    }

    #[test]
    fn test_config_file_operations() {
        let config = Config::default();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        config.save_to_file(&path).unwrap();
        let loaded_config = Config::load_from_file(&path).unwrap();

        assert_eq!(format!("{:?}", config), format!("{:?}", loaded_config));
    }
}

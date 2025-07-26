//! configuration management for Sylva

use crate::error::{Result, SylvaError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// main configuration for sylva
pub struct Config {
    /// storage backend settings
    pub storage: StorageConfig,
    /// hash algorithm settings
    pub hashing: HashingConfig,
    /// proof generation settings
    pub proof: ProofConfig,
    /// workspace behavior settings
    pub workspace: WorkspaceConfig,
    /// performance tuning settings
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// storage backend configuration
pub struct StorageConfig {
    /// which storage backend to use
    pub backend: StorageBackend,
    /// base directory for file storage
    pub base_path: Option<PathBuf>,
    /// cache size in bytes
    pub cache_size: Option<u64>,
    /// database connection string
    pub connection_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
/// available storage backends
pub enum StorageBackend {
    /// in-memory storage
    Memory,
    /// file-based storage
    Filesystem,
    /// database storage
    Database,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// hash algorithm configuration
pub struct HashingConfig {
    /// which hash algorithm to use
    pub algorithm: HashAlgorithm,
    /// enable parallel hashing for large files
    pub parallel_hashing: bool,
    /// chunk size for parallel processing
    pub chunk_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
/// hash algorithms we support
pub enum HashAlgorithm {
    /// sha-256 algorithm
    Sha256,
    /// blake3 algorithm
    Blake3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// proof generation settings
pub struct ProofConfig {
    /// how long proofs are valid (seconds)
    pub default_ttl: u64,
    /// cache generated proofs
    pub enable_caching: bool,
    /// max number of cached proofs
    pub max_cache_size: usize,
    /// compress proof data
    pub compress_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// workspace behavior settings
pub struct WorkspaceConfig {
    /// default workspace name
    pub default_name: String,
    /// auto-save interval in seconds
    pub auto_save_interval: u64,
    /// max workspace size in bytes
    pub max_size: Option<u64>,
    /// backup configuration
    pub backup: BackupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// backup settings
pub struct BackupConfig {
    /// enable automatic backups
    pub enabled: bool,
    /// backup interval in seconds
    pub interval: u64,
    /// maximum number of backups to keep
    pub max_backups: usize,
    /// directory to store backups
    pub backup_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// performance tuning options
pub struct PerformanceConfig {
    /// number of worker threads (auto if none)
    pub worker_threads: Option<usize>,
    /// memory pool size in bytes
    pub memory_pool_size: u64,
    /// use memory mapping for large files
    pub enable_mmap: bool,
    /// io buffer size in bytes
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
    /// load config from toml file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| SylvaError::config_error(format!("Failed to parse config: {}", e)))?;
        Ok(config)
    }

    /// save config to toml file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| SylvaError::config_error(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// load config from environment variables
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

    /// validate configuration settings
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
            StorageBackend::Memory => {}
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

    /// get actual number of worker threads to use
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

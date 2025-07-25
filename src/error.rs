//! error types

use thiserror::Error;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, SylvaError>;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum SylvaError {
    #[error("Entry not found: {id}")]
    EntryNotFound { id: Uuid },

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("I/O error: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
    },

    #[error("Version conflict: expected {expected}, found {actual}")]
    VersionConflict { expected: u64, actual: u64 },

    #[error("Serialization error: {source}")]
    SerializationError {
        #[from]
        source: serde_json::Error,
    },

    #[error("Storage error: {message}")]
    StorageError { message: String },

    #[error("Hash error: {message}")]
    HashError { message: String },

    #[error("Merkle tree error: {message}")]
    MerkleTreeError { message: String },

    #[error("Workspace error: {message}")]
    WorkspaceError { message: String },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("Resource already exists: {resource}")]
    AlreadyExists { resource: String },

    #[error("Operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl SylvaError {
    pub fn entry_not_found(id: Uuid) -> Self {
        Self::EntryNotFound { id }
    }

    pub fn invalid_proof<S: Into<String>>(reason: S) -> Self {
        Self::InvalidProof {
            reason: reason.into(),
        }
    }

    pub fn config_error<S: Into<String>>(message: S) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    pub fn version_conflict(expected: u64, actual: u64) -> Self {
        Self::VersionConflict { expected, actual }
    }

    pub fn storage_error<S: Into<String>>(message: S) -> Self {
        Self::StorageError {
            message: message.into(),
        }
    }

    pub fn hash_error<S: Into<String>>(message: S) -> Self {
        Self::HashError {
            message: message.into(),
        }
    }

    pub fn merkle_tree_error<S: Into<String>>(message: S) -> Self {
        Self::MerkleTreeError {
            message: message.into(),
        }
    }

    pub fn workspace_error<S: Into<String>>(message: S) -> Self {
        Self::WorkspaceError {
            message: message.into(),
        }
    }

    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    pub fn permission_denied<S: Into<String>>(operation: S) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }

    pub fn already_exists<S: Into<String>>(resource: S) -> Self {
        Self::AlreadyExists {
            resource: resource.into(),
        }
    }

    pub fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for SylvaError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal {
            message: err.to_string(),
        }
    }
}

//! error types

use thiserror::Error;
use uuid::Uuid;

/// convenience type alias for results
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

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl SylvaError {
    /// create entry not found error
    pub fn entry_not_found(id: Uuid) -> Self {
        Self::EntryNotFound { id }
    }

    /// create invalid proof error
    pub fn invalid_proof<S: Into<String>>(reason: S) -> Self {
        Self::InvalidProof {
            reason: reason.into(),
        }
    }

    /// create config error
    pub fn config_error<S: Into<String>>(message: S) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    /// create version conflict error
    pub fn version_conflict(expected: u64, actual: u64) -> Self {
        Self::VersionConflict { expected, actual }
    }

    /// create storage error
    pub fn storage_error<S: Into<String>>(message: S) -> Self {
        Self::StorageError {
            message: message.into(),
        }
    }

    /// create hash error
    pub fn hash_error<S: Into<String>>(message: S) -> Self {
        Self::HashError {
            message: message.into(),
        }
    }

    /// create merkle tree error
    pub fn merkle_tree_error<S: Into<String>>(message: S) -> Self {
        Self::MerkleTreeError {
            message: message.into(),
        }
    }

    /// create workspace error
    pub fn workspace_error<S: Into<String>>(message: S) -> Self {
        Self::WorkspaceError {
            message: message.into(),
        }
    }

    /// create invalid input error
    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// create permission denied error
    pub fn permission_denied<S: Into<String>>(operation: S) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }

    /// create already exists error
    pub fn already_exists<S: Into<String>>(resource: S) -> Self {
        Self::AlreadyExists {
            resource: resource.into(),
        }
    }

    /// create not found error
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound {
            resource: resource.into(),
        }
    }

    /// create timeout error
    pub fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    /// create internal error
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

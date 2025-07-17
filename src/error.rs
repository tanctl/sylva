use thiserror::Error;

#[derive(Error, Debug)]
pub enum SylvaError {
    #[error("Entry not found: {id}")]
    EntryNotFound { id: String },

    #[error("Invalid proof provided")]
    InvalidProof,

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("IO error: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
    },

    #[error("Version conflict: expected {expected}, found {found}")]
    VersionConflict { expected: String, found: String },

    #[error("JSON error: {source}")]
    JsonError {
        #[from]
        source: serde_json::Error,
    },

    #[error("Hash verification failed")]
    HashVerificationFailed,

    #[error("Tree structure is invalid")]
    InvalidTreeStructure,

    #[error("Storage backend error: {message}")]
    StorageError { message: String },

    #[error("Workspace error: {message}")]
    WorkspaceError { message: String },

    #[error("Ledger corruption detected")]
    LedgerCorruption,

    #[error("Invalid UUID format: {source}")]
    InvalidUuid {
        #[from]
        source: uuid::Error,
    },

    #[error("Proof generation failed: {reason}")]
    ProofGenerationFailed { reason: String },

    #[error("Merkle tree error: {message}")]
    MerkleTreeError { message: String },

    #[error("Access denied: {operation}")]
    AccessDenied { operation: String },

    #[error("Resource not available: {resource}")]
    ResourceUnavailable { resource: String },

    #[error("Proof error: {source}")]
    ProofError {
        #[from]
        source: crate::proof::ProofError,
    },

    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    #[error("Not found: {item_type} with identifier {identifier}")]
    NotFound {
        item_type: String,
        identifier: String,
    },

    #[error("Merge conflict: {message}")]
    MergeConflict { message: String },

    #[error("Validation error: {message}")]
    ValidationError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Invalid operation: {message}")]
    InvalidOperation { message: String },
}

impl From<Box<bincode::ErrorKind>> for SylvaError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        SylvaError::SerializationError {
            message: err.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, SylvaError>;

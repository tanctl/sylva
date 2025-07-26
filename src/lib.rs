//! versioned ledger and proof system for verifiable data

#![deny(clippy::all)]
#![warn(missing_docs)]

pub mod cli;
pub mod config;
pub mod error;
pub mod hash;
pub mod ledger;
pub mod proof;
pub mod storage;
pub mod tree;
pub mod workspace;

pub use error::{Result, SylvaError};

/// commonly used types and traits
pub mod prelude {
    pub use crate::{
        config::{Config, ConfigManager, ConfigSource, LegacyConfig},
        error::{Result, SylvaError},
        hash::{Blake3Hasher, Hash, HashOutput},
        ledger::Ledger,
        proof::Proof,
        storage::{ledger::LedgerSerializer, Storage},
        tree::MerkleTree,
        workspace::Workspace,
    };
}

/// current version from cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// project description from cargo.toml
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

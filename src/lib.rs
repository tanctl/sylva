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

pub mod prelude {
    pub use crate::{
        config::Config,
        error::{Result, SylvaError},
        hash::Hash,
        ledger::Ledger,
        proof::Proof,
        storage::Storage,
        tree::MerkleTree,
        workspace::Workspace,
    };
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

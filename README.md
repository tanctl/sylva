# Sylva

A high-performance versioned ledger and proof system for verifiable data with advanced cryptographic capabilities.

## Features

### Core Capabilities
- **Versioned Ledger System**: Track data changes with cryptographic integrity and automatic versioning
- **Multiple Hash Algorithms**: Support for Blake3, SHA-256, SHA-3, Keccak-256, and Poseidon
- **Tree Structures**: Binary Merkle trees, sparse trees, and Patricia tries for different use cases
- **Proof Generation**: Create and verify inclusion proofs for data integrity verification
- **Streaming Support**: Handle large datasets with streaming and temporal processing
- **Workspace Management**: Distributed workspace support with hierarchical configuration

### Advanced Features
- **Tree Optimization**: Automatic compaction, rebalancing, and storage cleanup
- **Batch Processing**: Efficient batch proof generation and verification with parallel processing
- **Data Compression**: Built-in compression with multiple algorithms (zstd, etc.)
- **Memory-Mapped Storage**: Efficient handling of large datasets with mmap support
- **Tree Visualization**: ASCII and DOT format tree visualization with proof path tracing
- **Performance Analysis**: Comprehensive benchmarking and profiling tools
- **Multiple Export Formats**: JSON, binary, and hex output formats
- **Security Features**: Constant-time verification, attack prevention, and malicious proof detection

## Installation

### Prerequisites
- Rust 1.70 or higher
- Cargo package manager

### Install from Git [Recommended]
```bash
cargo install --git https://github.com/tanctl/sylva
```

### Build from Source
```bash
git clone https://github.com/yourusername/sylva.git
cd sylva
cargo build --release
sudo cp target/release/sylva /usr/local/bin/
```

### Development Setup
```bash
# Install dependencies
cargo build

# Run tests
make test

# Run all quality gates
make check

# Generate documentation
make doc

# Run benchmarks
cargo bench
```

## Quick Start

### Initialize a Workspace
```bash
sylva init ./my-workspace
cd my-workspace
```

### Add Data to Ledger
```bash
# Add data with optional message
sylva add "Hello, World!" -m "First entry"

# Add data from file
sylva add @data.txt -m "File content"

# Commit multiple files
sylva commit document1.pdf document2.txt -m "Initial documents"

# Commit from stdin
cat data.json | sylva commit --stdin -m "API response data"
```

### Generate and Verify Proofs
```bash
# Generate proof for an entry
sylva prove <ledger-id> --entry-id <entry-id> --output proof.json

# Verify a proof
sylva verify proof.json --ledger <ledger-id>

# Batch proof generation
sylva prove <ledger-id> --batch --entries entry-list.txt --parallel
```

### Workspace Management
```bash
# Show workspace status
sylva status

# View ledger history
sylva history <ledger-id>

# List all entries
sylva list

# View ledger information
sylva info <ledger-id>

# Export data
sylva export <ledger-id> --format json --output backup.json
```

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Layer     │    │   Storage       │    │   Workspace     │
│   (Commands)    │◄──►│   (Persistence) │◄──►│   (Project Mgmt)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ledger        │    │   Merkle Tree   │    │   Config        │
│   (Data Mgmt)   │◄──►│   (Crypto       │◄──►│   (Settings)    │
│                 │    │    Proofs)      │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Hash System   │    │   Proof System  │    │   Cache Layer   │
│   (Crypto Hash) │◄──►│   (Verification)│◄──►│   (Performance) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Hash Algorithms

| Algorithm | Use Case | Performance | Security | Speed |
|-----------|----------|-------------|----------|-------|
| Blake3 (default) | General purpose | Fastest | High | ~3000 MB/s |
| SHA-256 | Legacy compatibility | Medium | High | ~400 MB/s |
| SHA-3 | Cryptographic applications | Medium | Highest | ~800 MB/s |
| Keccak-256 | Ethereum compatibility | Medium | High | ~800 MB/s |
| Poseidon | Zero-knowledge proofs | Slower | ZK-optimized | ~1200 MB/s |

### Tree Types

| Type | Use Case | Performance | Storage | Description |
|------|----------|-------------|---------|-------------|
| Binary | General purpose | Fast | Compact | Standard binary Merkle tree |
| Sparse | Large datasets with gaps | Memory efficient | Variable | Optimized for sparse data with built-in repair |
| Patricia | Key-value data | Fast lookups | Compressed | Radix tree for key-value storage with path compression |

## Commands Reference

### Core Commands

```bash
# Workspace Management
sylva init [PATH]                    # Initialize new workspace
sylva status                         # Show workspace status
sylva config get <KEY>              # Get configuration value
sylva config set <KEY> <VALUE>      # Set configuration value
sylva config list                   # List all configuration values

# Data Operations
sylva add <DATA>                    # Add data to ledger
sylva commit <FILES>...             # Commit files to ledger
sylva list                          # List all ledgers
sylva info <LEDGER>                 # Show ledger information
sylva history <LEDGER>              # Show version history

# Proof Operations
sylva prove <LEDGER> --entry-id <ID>  # Generate inclusion proof
sylva verify <PROOF>                   # Verify cryptographic proof

# Data Export/Import
sylva export <LEDGER>               # Export ledger data
sylva migrate                       # Migrate workspace format

# Optimization
sylva optimize                      # Optimize workspace
sylva compact <LEDGER>             # Compact specific ledger
sylva analyze                       # Analyze storage usage
sylva cleanup                       # Clean up workspace

# Visualization and Debugging
sylva visualize <LEDGER>           # Visualize tree structure
sylva debug <LEDGER>               # Debug tree analysis
sylva trace <LEDGER> <ENTRY-ID>    # Trace proof path
```

### Advanced Command Usage

#### Commit Options

```bash
# Commit with message
sylva commit file1.txt file2.txt -m "Added documentation"

# Commit from stdin
cat data.json | sylva commit --stdin -m "API response data"

# Specify hash function
sylva commit *.log --hash sha256 -m "Log files"

# Specify tree type
sylva commit data.csv --tree-type sparse -m "Sparse data"

# Binary format storage
sylva commit large_file.bin --format binary -m "Binary data"

# Streaming operations for large files
sylva commit large-dataset.csv --streaming --buffer-size 1MB
```

#### Proof Generation

```bash
# Single proof
sylva prove <ledger-id> --entry-id <entry-id> --output proof.json

# Batch proof generation
sylva prove <ledger-id> --batch --entries entry-list.txt --parallel

# Historical proof (specific version)
sylva prove <ledger-id> --entry-id <entry-id> --version 42

# Different output formats
sylva prove <ledger-id> --entry-id <entry-id> --format binary
sylva prove <ledger-id> --entry-id <entry-id> --format hex

# Memory-limited batch processing
sylva prove <ledger-id> --batch --memory-limit 1GB --chunk-size 1000
```

#### Verification

```bash
# Verify against current ledger
sylva verify proof.json --ledger <ledger-id>

# Verify against specific root hash
sylva verify proof.json --root a1b2c3d4e5f6...

# Verify against historical version
sylva verify proof.json --ledger <ledger-id> --version 42

# Batch verification
sylva verify batch-proofs.json --ledger <ledger-id> --parallel

# Strict verification with enhanced security
sylva verify proof.json --ledger <ledger-id> --strict
```

#### Tree Visualization

```bash
# Basic ASCII visualization
sylva visualize <ledger-id>

# DOT format for Graphviz
sylva visualize <ledger-id> --format dot --output tree.dot

# JSON format for web tools
sylva visualize <ledger-id> --format json --output tree.json

# Limited visualization options
sylva visualize <ledger-id> --max-depth 5 --max-nodes 50 --no-hashes

# Trace proof path
sylva trace <ledger-id> <entry-id> --format dot --output proof_trace.dot
```

### Optimization Commands

```bash
# Analyze workspace performance
sylva analyze

# Optimize storage and trees
sylva optimize --dry-run  # Preview changes
sylva optimize            # Apply optimizations

# Compact specific tree
sylva compact my_tree

# Clean up storage
sylva cleanup --dry-run
```

## Configuration

### Workspace Configuration

Sylva uses a hierarchical configuration system:

- **Global**: `~/.sylva/config.json` (user-wide settings)
- **Local**: `.sylva/config.json` (project-specific overrides)

```toml
# .sylva/config.toml
[general]
default_hash = "blake3"
cache_size = 1000
compression_level = 6
ledger_format = "json"
default_tree_type = "binary"
max_entry_size = 104857600
batch_size = 100
parallel_workers = 4
memory_limit = "1GB"

[storage]
use_compression = true
mmap_threshold = 1048576  # 1MB
cleanup_interval = 3600   # 1 hour

[optimization]
auto_compact = true
rebalance_threshold = 0.7
cleanup_on_exit = true
```

### Configuration Commands

```bash
# View configuration
sylva config list

# Set configuration values
sylva config set default_hash blake3
sylva config set cache_size 2000
sylva config set compression_level 6
```

## Security Features

### Cryptographic Security
- **Collision Resistance**: All hash functions provide 256-bit security
- **Preimage Resistance**: Computationally infeasible to reverse hashes
- **Merkle Tree Integrity**: Tamper-evident data structure
- **Immutable Ledger**: Entries cannot be modified after creation

### Attack Prevention
- **Constant-Time Verification**: Prevents timing attack vectors
- **Malicious Proof Detection**: Identifies suspicious hash patterns
- **Proof Depth Validation**: Protects against DoS through excessive depth
- **Size Consistency Checks**: Ensures proof integrity
- **Temporal Validation**: Confirms chronological consistency

## Performance

### Benchmarks
- **Hash Performance**: Up to 3GB/s throughput with Blake3
- **Tree Operations**: O(log n) insertion and proof generation
- **Storage Efficiency**: 10-30% space savings after optimization
- **Memory Usage**: Efficient memory-mapped storage for large datasets

### Running Benchmarks
```bash
# All benchmarks
cargo bench

# Specific benchmark categories
cargo bench hash_benchmarks
cargo bench batch_proof_benchmarks
cargo bench compression_benchmarks
cargo bench optimization_benchmarks
```

### Optimization Features
- Automatic tree compaction and rebalancing
- Redundant data removal
- Storage cleanup and garbage collection
- Performance analysis and recommendations

### Batch Operations
For high-performance scenarios:

```bash
# Parallel proof generation
sylva prove <ledger-id> --batch --parallel --entries large-list.txt

# Memory-limited batch processing
sylva prove <ledger-id> --batch --memory-limit 1GB --chunk-size 1000

# Streaming operations for large files
sylva commit large-dataset.csv --streaming --buffer-size 1MB
```

## Visualization

### Tree Structure Visualization
```bash
# Visualize tree structure
sylva visualize --tree my_tree --output tree.svg

# Generate performance charts
sylva visualize --type performance --output perf.png

# Create DOT files for Graphviz
dot -Tpng tree.dot -o tree.png
dot -Tsvg tree.dot -o tree.svg
```

### Proof Path Tracing
```bash
# Trace proof path with visualization
sylva trace <ledger-id> <entry-id> --format dot --output proof_trace.dot

# JSON format for web integration
sylva trace <ledger-id> <entry-id> --format json --output proof_trace.json
```

## Examples

### Legal Document Verification

```bash
# Set up legal document workspace
sylva init legal-contracts
cd legal-contracts

# Add contracts with metadata
sylva commit contract-2024-001.pdf contract-2024-002.pdf \
    -m "Q1 2024 contracts"

# Generate proof for audit
sylva prove <ledger-id> --entry-id <contract-id> \
    --output audit-proof-2024-001.json

# Verify during audit
sylva verify audit-proof-2024-001.json --ledger <ledger-id>
```

### Research Data Integrity

```bash
# Create research workspace
sylva init research-data
cd research-data

# Commit experiment data with specific tree type
sylva commit experiment-data.csv raw-measurements.json \
    --tree-type sparse -m "Experiment 1 - sparse data structure"

# Generate proof for publication
sylva prove <ledger-id> --entry-id <data-id> \
    --output publication-proof.json

# Verify data integrity
sylva verify publication-proof.json --ledger <ledger-id>
```

### Supply Chain Tracking

```bash
# Initialize supply chain ledger
sylva init supply-chain
cd supply-chain

# Track item through supply chain
sylva commit item-manifest.json quality-cert.pdf shipping-doc.pdf \
    -m "Item ABC123 - manufactured 2024-01-15"

# Generate proof of authenticity
sylva prove <ledger-id> --entry-id <item-id> \
    --output authenticity-proof.json

# Verify authenticity
sylva verify authenticity-proof.json --ledger <ledger-id>
```

### Large Dataset Processing

```bash
# Process large datasets efficiently
sylva init big-data
cd big-data

# Use streaming for large files
sylva commit large-log-file.txt --streaming --buffer-size 10MB \
    -m "Large log file processing"

# Batch operations
sylva prove <ledger-id> --batch --parallel --entries batch-list.txt

# Optimize after processing
sylva optimize
```

## API Reference

### Core Types
```rust
use sylva::{
    ledger::Ledger,
    tree::{BinaryMerkleTree, Tree},
    proof::Proof,
    workspace::Workspace,
};

// Create a new ledger
let mut ledger = Ledger::new();

// Add entry
let entry_id = ledger.add_entry(b"data".to_vec())?;

// Create tree and generate proof
let mut tree = BinaryMerkleTree::new();
let proof = tree.generate_proof(&entry_id)?;

// Verify proof
assert!(proof.verify()?);
```

### Workspace Management
```rust
use sylva::workspace::Workspace;

// Initialize workspace
let workspace = Workspace::initialize("./my-workspace")?;

// Load existing workspace
let workspace = Workspace::find_workspace()?;

// Configuration
workspace.set_config_value("default_hash", "blake3")?;
let hash_alg = workspace.get_config_value("default_hash")?;
```

### Hash Operations
```rust
use sylva::hash::{Blake3Hasher, Hash};

let hasher = Blake3Hasher::new();
let data = b"test data";
let hash = hasher.hash_bytes(data)?;
assert_eq!(hash.as_bytes().len(), 32);
```

### Tree Operations
```rust
use sylva::tree::{binary::BinaryMerkleTree, Tree};

let mut tree = BinaryMerkleTree::new();
let entry = ledger::LedgerEntry::new(b"test data".to_vec(), 1);
tree.insert(entry)?;
```

### Proof Generation and Verification
```rust
use sylva::proof::Proof;

let proof = Proof::new("test-id".to_string());
assert_eq!(proof.entry_id, "test-id");
assert!(proof.verify()?);
```

## Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test optimization_tests
cargo test --test verify_integration_tests

# Run with release optimizations
cargo test --release

# Run benchmarks
cargo bench

# Test with coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out html
```

### Test Structure
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Benchmarks**: Performance and optimization testing
- **Property Tests**: Randomized testing with proptest

## Development

### Project Structure
```
sylva/
├── src/
│   ├── main.rs         # CLI entry point
│   ├── lib.rs          # Library exports
│   ├── error.rs        # Error handling
│   ├── cache/          # Caching layer
│   ├── cli/            # Command-line interface
│   │   ├── commit.rs   # Data commit operations
│   │   ├── export.rs   # Data export functionality
│   │   ├── info.rs     # Ledger inspection
│   │   ├── optimize.rs # Optimization tools
│   │   ├── prove.rs    # Proof generation
│   │   ├── verify.rs   # Proof verification
│   │   └── visualize.rs # Tree visualization
│   ├── config/         # Configuration management
│   ├── hash/           # Hash algorithm implementations
│   │   ├── blake3.rs   # Blake3 implementation
│   │   ├── keccak.rs   # Keccak-256 implementation
│   │   ├── poseidon.rs # Poseidon hash implementation
│   │   └── sha256.rs   # SHA-256 implementation
│   ├── ledger/         # Core ledger functionality
│   ├── proof/          # Proof generation and verification
│   │   ├── batch.rs    # Batch proof operations
│   │   ├── inclusion.rs # Inclusion proofs
│   │   └── sparse.rs   # Sparse proofs
│   ├── storage/        # Storage backends
│   │   ├── compression.rs # Data compression
│   │   └── mmap.rs     # Memory-mapped files
│   ├── streaming/      # Streaming and temporal processing
│   ├── tree/           # Tree implementations
│   │   ├── binary.rs   # Binary Merkle tree
│   │   ├── patricia.rs # Patricia trie
│   │   └── sparse.rs   # Sparse tree
│   └── workspace/      # Workspace management
├── tests/              # Integration tests
├── benches/            # Performance benchmarks
├── examples/           # Usage examples
└── docs/               # Documentation
```

## License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments
- Built with [Rust](https://www.rust-lang.org/) for performance and safety
- [Blake3](https://github.com/BLAKE3-team/BLAKE3) for high-performance hashing
- [Clap](https://github.com/clap-rs/clap) for command-line interface
- [Serde](https://github.com/serde-rs/serde) for serialization
- [Rayon](https://github.com/rayon-rs/rayon) for parallel processing
- Uses industry-standard cryptographic libraries
- Inspired by Git's versioning and blockchain's cryptographic guarantees
- Optimized for both development and production use

## Support
- **Documentation**: Run `cargo doc --open` for detailed API docs
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join the community discussions for help and ideas

---

*Sylva: Building the future of verifiable data systems*
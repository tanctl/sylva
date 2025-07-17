pub mod commit;
pub mod compare;
pub mod export;
pub mod info;
pub mod optimize;
pub mod prove;
pub mod verify;
pub mod visualize;

use crate::error::Result;
use clap::{Arg, ArgMatches, Command};

/// Handle CLI commands
pub fn handle_command(command: &str, _args: &[String]) -> Result<()> {
    match command {
        "init" => println!("Initializing workspace"),
        "add" => println!("Adding entry"),
        "commit" => {
            // This will be replaced by proper commit handling
            println!("Committing entries");
        }
        "verify" => println!("Verifying proof"),
        _ => println!("Unknown command: {}", command),
    }
    Ok(())
}

/// Build the commit subcommand
pub fn build_commit_command() -> Command {
    Command::new("commit")
        .about("Create versioned ledger entries from files or stdin")
        .long_about("Create versioned ledger entries with automatic timestamping and conflict detection. Supports both file input and stdin for piped data.")
        .arg(
            Arg::new("tree-type")
                .long("tree-type")
                .help("Tree type to use (binary, sparse, patricia)")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .default_value("binary")
        )
        .arg(
            Arg::new("files")
                .help("Files to commit as ledger entries")
                .value_name("FILES")
                .num_args(0..)
                .action(clap::ArgAction::Append)
        )
        .arg(
            Arg::new("message")
                .short('m')
                .long("message")
                .help("Commit message describing the changes")
                .value_name("MESSAGE")
        )
        .arg(
            Arg::new("stdin")
                .long("stdin")
                .help("Read data from stdin instead of files")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("auto-timestamp")
                .long("auto-timestamp")
                .help("Automatically add timestamps to entries")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Force commit even if version conflicts exist")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("progress")
                .long("progress")
                .help("Show progress bar for large operations")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be committed without actually committing")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Build the info subcommand
pub fn build_info_command() -> Command {
    Command::new("info")
        .about("Show detailed information about a ledger")
        .long_about("Display comprehensive statistics about a ledger including entry count, size, versions, hash function, and integrity status.")
        .arg(
            Arg::new("tree-type")
                .long("tree-type")
                .help("Tree type to use (binary, sparse, patricia)")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .default_value("binary")
        )
        .arg(
            Arg::new("ledger")
                .help("Name of the ledger to show info for")
                .value_name("LEDGER_NAME")
                .required(true)
        )
}

/// Build the history subcommand
pub fn build_history_command() -> Command {
    Command::new("history")
        .about("Show version timeline for a ledger")
        .long_about("Display the version timeline of a ledger with timestamps, descriptions, and entry metadata.")
        .arg(
            Arg::new("ledger")
                .help("Name of the ledger to show history for")
                .value_name("LEDGER_NAME")
                .required(true)
        )
        .arg(
            Arg::new("limit")
                .short('n')
                .long("limit")
                .help("Maximum number of entries to show")
                .value_name("LIMIT")
                .default_value("20")
        )
}

/// Build the list subcommand
pub fn build_list_command() -> Command {
    Command::new("list")
        .about("List all ledgers in the workspace")
        .long_about("Show a summary of all ledgers in the current workspace with basic statistics and integrity status.")
}

/// Build the export subcommand
pub fn build_export_command() -> Command {
    Command::new("export")
        .about("Export ledger tree in various formats")
        .long_about("Export a ledger's Merkle tree structure and data in JSON, binary, or hex format for analysis, backup, or debugging.")
        .arg(
            Arg::new("tree-type")
                .long("tree-type")
                .help("Tree type to use (binary, sparse, patricia)")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .default_value("binary")
        )
        .arg(
            Arg::new("ledger")
                .help("Name of the ledger to export")
                .value_name("LEDGER_NAME")
                .required(true)
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Export format")
                .value_name("FORMAT")
                .value_parser(["json", "binary", "bin", "hex"])
                .default_value("json")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file path")
                .value_name("FILE")
        )
        .arg(
            Arg::new("compact")
                .long("compact")
                .help("Use compact output (no pretty printing)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-metadata")
                .long("no-metadata")
                .help("Exclude metadata from export")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-validate")
                .long("no-validate")
                .help("Skip output validation")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("chunk-size")
                .long("chunk-size")
                .help("Chunk size for streaming (bytes)")
                .value_name("SIZE")
                .default_value("1048576")
        )
}

/// Handle the commit command
pub fn handle_commit_command(matches: &ArgMatches) -> Result<()> {
    commit::CommitCommand::from_args(matches)?.execute()
}

/// Handle the info command
pub fn handle_info_command(matches: &ArgMatches) -> Result<()> {
    info::handle_info_command(matches)
}

/// Handle the history command
pub fn handle_history_command(matches: &ArgMatches) -> Result<()> {
    info::handle_history_command(matches)
}

/// Handle the list command
pub fn handle_list_command(matches: &ArgMatches) -> Result<()> {
    info::handle_list_command(matches)
}

/// Handle the export command
pub fn handle_export_command(matches: &ArgMatches) -> Result<()> {
    export::handle_export_command(matches)
}

/// Build the verify subcommand
pub fn build_verify_command() -> Command {
    Command::new("verify")
        .about("Verify inclusion proofs with version and temporal awareness")
        .long_about("Verify inclusion proofs against stored ledgers or historical states. Supports single proof verification, batch verification, and version conflict detection with detailed reporting.")
        .arg(
            Arg::new("proof_files")
                .help("Proof files to verify")
                .value_name("FILES")
                .num_args(1..)
                .action(clap::ArgAction::Append)
                .required(true)
        )
        .arg(
            Arg::new("ledger")
                .long("ledger")
                .help("Verify against stored ledger")
                .value_name("LEDGER_NAME")
                .conflicts_with_all(["root", "version"])
        )
        .arg(
            Arg::new("root")
                .long("root")
                .help("Root hash for historical verification")
                .value_name("HASH")
                .conflicts_with("ledger")
        )
        .arg(
            Arg::new("version")
                .long("version")
                .help("Version timestamp for historical verification")
                .value_name("TIMESTAMP")
                .conflicts_with("ledger")
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Suppress detailed output")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("performance")
                .long("performance")
                .help("Show performance metrics")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-temporal-check")
                .long("no-temporal-check")
                .help("Skip temporal consistency validation")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-version-check")
                .long("no-version-check")
                .help("Skip version constraint enforcement")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("batch-size")
                .long("batch-size")
                .help("Maximum batch size for processing")
                .value_name("SIZE")
                .default_value("1000")
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .help("Timeout for verification in seconds")
                .value_name("SECONDS")
                .default_value("300")
        )
}

/// Build the prove subcommand
pub fn build_prove_command() -> Command {
    Command::new("prove")
        .about("Generate inclusion proofs for ledger entries")
        .long_about("Generate inclusion proofs for ledger entries with version awareness and historical state support. Supports single entry proofs, content-based proofs, version-specific proofs, and batch operations.")
        .arg(
            Arg::new("tree-type")
                .long("tree-type")
                .help("Tree type to use (binary, sparse, patricia)")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .default_value("binary")
        )
        .arg(
            Arg::new("ledger")
                .help("Name of the ledger to prove entries from")
                .value_name("LEDGER_NAME")
                .required(true)
        )
        .arg(
            Arg::new("entry-id")
                .long("entry-id")
                .help("Entry ID to generate proof for")
                .value_name("UUID")
                .conflicts_with_all(["data", "version", "batch"])
        )
        .arg(
            Arg::new("data")
                .long("data")
                .help("Data content to generate proof for (hex encoded)")
                .value_name("HEX")
                .conflicts_with_all(["entry-id", "version", "batch"])
        )
        .arg(
            Arg::new("version")
                .long("version")
                .help("Generate proof for historical state at timestamp")
                .value_name("TIMESTAMP")
                .conflicts_with_all(["entry-id", "data", "batch"])
        )
        .arg(
            Arg::new("batch")
                .long("batch")
                .help("Generate batch proofs from entry list file")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["entry-id", "data", "version"])
        )
        .arg(
            Arg::new("entries")
                .long("entries")
                .help("File containing entry IDs for batch proving")
                .value_name("FILE")
                .requires("batch")
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Proof output format")
                .value_name("FORMAT")
                .value_parser(["json", "binary", "bin", "hex"])
                .default_value("json")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file path")
                .value_name("FILE")
        )
        .arg(
            Arg::new("compact")
                .long("compact")
                .help("Use compact output (no pretty printing)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-metadata")
                .long("no-metadata")
                .help("Exclude metadata from proof")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-version-info")
                .long("no-version-info")
                .help("Exclude version information from proof")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-progress")
                .long("no-progress")
                .help("Disable progress reporting")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("batch-size")
                .long("batch-size")
                .help("Batch size for batch operations")
                .value_name("SIZE")
                .default_value("100")
        )
}

/// Handle the verify command
pub fn handle_verify_command(matches: &ArgMatches) -> Result<()> {
    verify::handle_verify_command(matches)
}

/// Handle the prove command
pub fn handle_prove_command(matches: &ArgMatches) -> Result<()> {
    prove::handle_prove_command(matches)
}

/// Build the migrate subcommand
pub fn build_migrate_command() -> Command {
    Command::new("migrate")
        .about("Migrate between different tree types")
        .long_about(
            "Convert a ledger from one tree type to another while preserving data integrity.",
        )
        .arg(
            Arg::new("source-tree-type")
                .long("from")
                .help("Source tree type")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .required(true),
        )
        .arg(
            Arg::new("target-tree-type")
                .long("to")
                .help("Target tree type")
                .value_name("TYPE")
                .value_parser(["binary", "sparse", "patricia"])
                .required(true),
        )
        .arg(
            Arg::new("ledger")
                .help("Name of the ledger to migrate")
                .value_name("LEDGER_NAME")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output ledger name (defaults to input name with suffix)")
                .value_name("OUTPUT_NAME"),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Force migration even if incompatible")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("validate")
                .long("validate")
                .help("Validate migration result")
                .action(clap::ArgAction::SetTrue),
        )
}

/// Build the compare subcommand
pub fn build_compare_command() -> Command {
    Command::new("compare")
        .about("Compare and merge ledgers with temporal conflict resolution")
        .long_about("Git-like comparison and merging functionality for versioned ledgers with temporal awareness and conflict resolution strategies.")
        .subcommand_required(true)
        .subcommand(
            Command::new("diff")
                .about("Compare two ledgers and show differences")
                .arg(
                    Arg::new("ledger_a")
                        .help("First ledger ID to compare")
                        .value_name("LEDGER_A")
                        .required(true)
                )
                .arg(
                    Arg::new("ledger_b")
                        .help("Second ledger ID to compare")
                        .value_name("LEDGER_B")
                        .required(true)
                )
                .arg(
                    Arg::new("temporal")
                        .long("temporal")
                        .help("Show detailed temporal changes")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("summary")
                        .long("summary")
                        .help("Show only summary statistics")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .help("Output format (text, json, csv)")
                        .value_name("FORMAT")
                        .value_parser(["text", "json", "csv"])
                        .default_value("text")
                )
                .arg(
                    Arg::new("content")
                        .long("content")
                        .help("Include entry content in diff")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("version_range")
                        .long("version-range")
                        .help("Version range to compare (format: start..end)")
                        .value_name("RANGE")
                )
        )
        .subcommand(
            Command::new("merge")
                .about("Merge two ledgers using specified strategy")
                .arg(
                    Arg::new("source")
                        .help("Source ledger ID to merge from")
                        .value_name("SOURCE")
                        .required(true)
                )
                .arg(
                    Arg::new("target")
                        .help("Target ledger ID to merge into")
                        .value_name("TARGET")
                        .required(true)
                )
                .arg(
                    Arg::new("output")
                        .help("Output ledger name for merge result")
                        .value_name("OUTPUT")
                        .required(true)
                )
                .arg(
                    Arg::new("strategy")
                        .long("strategy")
                        .help("Merge strategy to use")
                        .value_name("STRATEGY")
                        .value_parser(["timestamp", "last-writer-wins", "manual", "interactive", "fail-on-conflict"])
                        .default_value("timestamp")
                )
                .arg(
                    Arg::new("dry_run")
                        .long("dry-run")
                        .help("Show what would be merged without executing")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Force merge even with conflicts")
                        .action(clap::ArgAction::SetTrue)
                )
                .arg(
                    Arg::new("resolution_file")
                        .long("resolution-file")
                        .help("Manual conflict resolution file")
                        .value_name("FILE")
                )
        )
        .subcommand(
            Command::new("status")
                .about("Show merge status and conflicts")
                .arg(
                    Arg::new("ledger_id")
                        .help("Ledger ID to check merge status")
                        .value_name("LEDGER_ID")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("validate")
                .about("Validate a merge result")
                .arg(
                    Arg::new("ledger_id")
                        .help("Ledger ID to validate")
                        .value_name("LEDGER_ID")
                        .required(true)
                )
                .arg(
                    Arg::new("strict")
                        .long("strict")
                        .help("Strict validation mode")
                        .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("rollback")
                .about("Rollback a merge operation")
                .arg(
                    Arg::new("ledger_id")
                        .help("Ledger ID to rollback")
                        .value_name("LEDGER_ID")
                        .required(true)
                )
                .arg(
                    Arg::new("target_version")
                        .help("Version to rollback to")
                        .value_name("VERSION")
                        .required(true)
                )
                .arg(
                    Arg::new("confirm")
                        .long("confirm")
                        .help("Confirm rollback operation")
                        .action(clap::ArgAction::SetTrue)
                )
        )
}

/// Handle the compare command
pub fn handle_compare_command(matches: &ArgMatches) -> Result<()> {
    compare::handle_compare_command(matches)
}

/// Build the optimize subcommand
pub fn build_optimize_command() -> Command {
    Command::new("optimize")
        .about("Optimize tree storage and performance")
        .long_about("Analyze and optimize workspace trees for better storage efficiency and access patterns. Includes tree compaction, rebalancing, and storage cleanup.")
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be optimized without making changes")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show detailed optimization report")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Force optimization even if risky")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Build the compact subcommand
pub fn build_compact_command() -> Command {
    Command::new("compact")
        .about("Compact a specific tree to remove unused nodes")
        .long_about("Remove unused and redundant nodes from a specific tree to reduce storage size and improve performance.")
        .arg(
            Arg::new("tree")
                .help("Name of the tree to compact")
                .value_name("TREE_NAME")
                .required(true)
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be compacted without making changes")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Build the analyze subcommand
pub fn build_analyze_command() -> Command {
    Command::new("analyze")
        .about("Analyze workspace storage and performance")
        .long_about("Generate comprehensive analysis of workspace storage usage, compression opportunities, and performance bottlenecks.")
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Output format")
                .value_name("FORMAT")
                .value_parser(["text", "json", "csv"])
                .default_value("text")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file path")
                .value_name("FILE")
        )
}

/// Build the cleanup subcommand
pub fn build_cleanup_command() -> Command {
    Command::new("cleanup")
        .about("Clean up workspace storage")
        .long_about("Remove unused files, temporary data, and perform storage garbage collection to free up space.")
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would be cleaned up without making changes")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Force cleanup without confirmation")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("aggressive")
                .long("aggressive")
                .help("Perform aggressive cleanup including cached data")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Handle the optimize command
pub fn handle_optimize_command(matches: &ArgMatches) -> Result<()> {
    optimize::handle_optimize_command(matches)
}

/// Handle the compact command
pub fn handle_compact_command(matches: &ArgMatches) -> Result<()> {
    optimize::handle_compact_command(matches)
}

/// Handle the analyze command
pub fn handle_analyze_command(matches: &ArgMatches) -> Result<()> {
    optimize::handle_analyze_command(matches)
}

/// Handle the cleanup command
pub fn handle_cleanup_command(matches: &ArgMatches) -> Result<()> {
    optimize::handle_cleanup_command(matches)
}

/// Build the visualize subcommand
pub fn build_visualize_command() -> Command {
    Command::new("visualize")
        .about("Visualize tree structures")
        .long_about("Generate visual representations of tree structures in various formats including ASCII for terminal display, DOT for Graphviz, and JSON for web tools.")
        .arg(
            Arg::new("tree")
                .help("Name of the tree to visualize")
                .value_name("TREE_NAME")
                .required(true)
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Output format")
                .value_name("FORMAT")
                .value_parser(["ascii", "dot", "json"])
                .default_value("ascii")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file path")
                .value_name("FILE")
        )
        .arg(
            Arg::new("max-depth")
                .long("max-depth")
                .help("Maximum depth to display")
                .value_name("DEPTH")
        )
        .arg(
            Arg::new("max-nodes")
                .long("max-nodes")
                .help("Maximum number of nodes to display")
                .value_name("COUNT")
        )
        .arg(
            Arg::new("no-hashes")
                .long("no-hashes")
                .help("Hide hash values")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("metadata")
                .long("metadata")
                .help("Show node metadata")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Build the debug subcommand
pub fn build_debug_command() -> Command {
    Command::new("debug")
        .about("Debug tree structure and analyze issues")
        .long_about("Analyze tree structure for potential issues, validate integrity, and provide debugging information.")
        .arg(
            Arg::new("tree")
                .help("Name of the tree to debug")
                .value_name("TREE_NAME")
                .required(true)
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show detailed debugging information")
                .action(clap::ArgAction::SetTrue)
        )
}

/// Build the trace subcommand
pub fn build_trace_command() -> Command {
    Command::new("trace")
        .about("Trace and visualize proof paths")
        .long_about("Generate visual representations of Merkle proof paths to aid in debugging and verification.")
        .arg(
            Arg::new("tree")
                .help("Name of the tree containing the entry")
                .value_name("TREE_NAME")
                .required(true)
        )
        .arg(
            Arg::new("entry-id")
                .help("UUID of the entry to trace")
                .value_name("ENTRY_ID")
                .required(true)
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .help("Output format")
                .value_name("FORMAT")
                .value_parser(["ascii", "dot", "json"])
                .default_value("ascii")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Output file path")
                .value_name("FILE")
        )
}

/// Handle the visualize command
pub fn handle_visualize_command(matches: &ArgMatches) -> Result<()> {
    visualize::handle_visualize_command(matches)
}

/// Handle the debug command
pub fn handle_debug_command(matches: &ArgMatches) -> Result<()> {
    visualize::handle_debug_command(matches)
}

/// Handle the trace command
pub fn handle_trace_command(matches: &ArgMatches) -> Result<()> {
    visualize::handle_proof_trace_command(matches)
}

/// Handle the migrate command
pub fn handle_migrate_command(matches: &ArgMatches) -> Result<()> {
    use crate::tree::{TreeFactory, TreeType, TreeTypeDetector, UnifiedTree};
    use crate::workspace::Workspace;
    use std::fs;
    use std::time::SystemTime;

    let source_type_str = matches.get_one::<String>("source-tree-type").unwrap();
    let target_type_str = matches.get_one::<String>("target-tree-type").unwrap();
    let ledger_name = matches.get_one::<String>("ledger").unwrap();
    let output_name = matches
        .get_one::<String>("output")
        .cloned()
        .unwrap_or_else(|| format!("{}_migrated_to_{}", ledger_name, target_type_str));
    let force = matches.get_flag("force");
    let validate = matches.get_flag("validate");

    let source_type: TreeType = source_type_str.parse()?;
    let target_type: TreeType = target_type_str.parse()?;

    if source_type == target_type {
        println!("Source and target tree types are the same. No migration needed.");
        return Ok(());
    }

    // Find workspace
    let workspace = Workspace::find_workspace()?;

    // Check if migration is enabled in configuration
    if !workspace.config().get_tree_migration_enabled() {
        return Err(crate::error::SylvaError::ConfigError {
            message: "Tree migration is disabled in configuration. Enable with tree_migration_enabled = true".to_string()
        });
    }

    let factory = TreeFactory::new();

    // Enhanced migration compatibility checking
    if !force && !factory.can_migrate(source_type, target_type) {
        // Check if migration is possible through intermediate steps
        let migration_path = factory.migration_path(source_type, target_type);
        if migration_path.is_empty() || migration_path.len() == 1 {
            return Err(crate::error::SylvaError::InvalidInput {
                message: format!("Cannot migrate from {} to {}. No migration path found. Use --force to attempt anyway.",
                    source_type.as_str(), target_type.as_str())
            });
        } else {
            println!(
                "Multi-step migration path found: {:?}",
                migration_path
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
            );
            println!(
                "This will require {} intermediate steps.",
                migration_path.len() - 2
            );
        }
    }

    let start_time = SystemTime::now();
    println!(
        "Migrating ledger '{}' from {} to {}...",
        ledger_name,
        source_type.as_str(),
        target_type.as_str()
    );

    // Load source tree data
    let source_tree_path =
        workspace
            .ledgers_path()
            .join(format!("{}_{}.tree", ledger_name, source_type.as_str()));
    let source_tree = if source_tree_path.exists() {
        println!(
            "Loading existing source tree from {}",
            source_tree_path.display()
        );

        // Use detector to verify the tree type
        let detector = TreeTypeDetector::new();
        let detection_result = detector.detect_from_file(&source_tree_path)?;

        if !detection_result.is_reliable || detection_result.detected_type != Some(source_type) {
            if !force {
                return Err(crate::error::SylvaError::InvalidInput {
                    message: format!("Source tree file type detection failed or mismatch. Detected: {:?}, Expected: {:?}. Use --force to proceed.",
                        detection_result.detected_type, source_type)
                });
            }
            println!("Warning: Tree type detection mismatch, proceeding with --force");
        }

        // Load tree from file
        let data = fs::read(&source_tree_path)?;
        if let Ok(export_data) = bincode::deserialize::<crate::tree::TreeExportData>(&data) {
            let mut tree = UnifiedTree::new(source_type);
            tree.import_from_migration(export_data)?;
            tree
        } else {
            return Err(crate::error::SylvaError::InvalidInput {
                message: format!(
                    "Failed to deserialize source tree from {}",
                    source_tree_path.display()
                ),
            });
        }
    } else {
        println!("Warning: Source tree file not found, creating empty tree");
        UnifiedTree::new(source_type)
    };

    // Report source tree statistics
    let source_stats = source_tree.statistics();
    println!("Source tree statistics:");
    println!("  Type: {}", source_stats.tree_type.as_str());
    println!("  Entries: {}", source_stats.entry_count);
    println!(
        "  Memory usage: {} bytes",
        source_stats.memory_usage.total_bytes
    );
    println!(
        "  Memory efficiency: {:.1}%",
        source_stats.memory_usage.efficiency() * 100.0
    );

    // Perform migration
    println!("Performing migration...");
    let migrated_tree = if factory.can_migrate(source_type, target_type) {
        // Direct migration
        source_tree.migrate_to(target_type)?
    } else if force {
        // Multi-step migration through intermediate types
        let migration_path = factory.migration_path(source_type, target_type);
        if migration_path.len() > 2 {
            let mut current_tree = source_tree;
            for (i, &intermediate_type) in migration_path[1..].iter().enumerate() {
                println!(
                    "  Step {}: Migrating to {} tree",
                    i + 1,
                    intermediate_type.as_str()
                );
                current_tree = current_tree.migrate_to(intermediate_type)?;

                // Validate intermediate step if requested
                if validate && !current_tree.validate()? {
                    return Err(crate::error::SylvaError::InvalidInput {
                        message: format!("Intermediate migration step {} failed validation", i + 1),
                    });
                }
            }
            current_tree
        } else {
            source_tree.migrate_to(target_type)?
        }
    } else {
        return Err(crate::error::SylvaError::InvalidInput {
            message: "Migration not supported without --force flag".to_string(),
        });
    };

    // Report migrated tree statistics
    let migrated_stats = migrated_tree.statistics();
    println!("Migrated tree statistics:");
    println!("  Type: {}", migrated_stats.tree_type.as_str());
    println!("  Entries: {}", migrated_stats.entry_count);
    println!(
        "  Memory usage: {} bytes",
        migrated_stats.memory_usage.total_bytes
    );
    println!(
        "  Memory efficiency: {:.1}%",
        migrated_stats.memory_usage.efficiency() * 100.0
    );

    // Compare migration efficiency
    if source_stats.entry_count > 0 {
        let size_change = (migrated_stats.memory_usage.total_bytes as f64
            / source_stats.memory_usage.total_bytes as f64)
            * 100.0;
        let efficiency_change = (migrated_stats.memory_usage.efficiency()
            - source_stats.memory_usage.efficiency())
            * 100.0;

        println!("Migration impact:");
        println!("  Size change: {:.1}%", size_change - 100.0);
        println!(
            "  Efficiency change: {:+.1} percentage points",
            efficiency_change
        );
    }

    if validate {
        println!("Validating migrated tree...");
        if migrated_tree.validate()? {
            println!("✓ Migration validation successful");
        } else {
            println!("✗ Migration validation failed");
            return Err(crate::error::SylvaError::InvalidInput {
                message: "Migration validation failed".to_string(),
            });
        }
    }

    // Save migrated tree
    let output_path =
        workspace
            .ledgers_path()
            .join(format!("{}_{}.tree", output_name, target_type.as_str()));
    let export_data = migrated_tree.export_for_migration(target_type)?;
    let serialized = bincode::serialize(&export_data).map_err(|e| {
        crate::error::SylvaError::MerkleTreeError {
            message: format!("Failed to serialize migrated tree: {}", e),
        }
    })?;

    fs::write(&output_path, serialized)?;

    // Calculate migration duration
    let duration = start_time.elapsed().unwrap_or_default();

    println!(
        "✓ Migration completed successfully in {:.2}s",
        duration.as_secs_f64()
    );
    println!("  Output file: {}", output_path.display());
    println!("  Entries: {}", migrated_tree.entry_count());
    println!("  Tree type: {}", migrated_tree.tree_type().as_str());

    // Suggest next steps
    if migrated_tree.entry_count() > 0 {
        println!("\nNext steps:");
        println!(
            "  • Verify the migrated tree: sylva info --ledger {} --tree-type {}",
            output_name,
            target_type.as_str()
        );
        println!(
            "  • Update workspace config to use new tree type: default_tree_type = \"{}\"",
            target_type.as_str()
        );
        if output_name != *ledger_name {
            println!("  • Consider renaming the output to replace the original ledger");
        }
    }

    Ok(())
}

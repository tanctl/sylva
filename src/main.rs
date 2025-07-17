use anyhow::Result;
use clap::{Arg, Command};
use sylva::cli::{
    build_analyze_command, build_cleanup_command, build_commit_command, build_compact_command,
    build_debug_command, build_export_command, build_history_command, build_info_command,
    build_list_command, build_migrate_command, build_optimize_command, build_prove_command,
    build_trace_command, build_verify_command, build_visualize_command, handle_analyze_command,
    handle_cleanup_command, handle_commit_command, handle_compact_command, handle_debug_command,
    handle_export_command, handle_history_command, handle_info_command, handle_list_command,
    handle_migrate_command, handle_optimize_command, handle_prove_command, handle_trace_command,
    handle_verify_command, handle_visualize_command,
};
use sylva::workspace::Workspace;

fn main() -> Result<()> {
    let matches = Command::new("sylva")
        .version("0.1.0")
        .about("A versioned ledger and proof system for verifiable data")
        .long_about("Sylva provides a robust, versioned ledger system with cryptographic proofs for data verification. It supports distributed workspaces, Merkle tree-based proofs, and flexible storage backends.")
        .subcommand(
            Command::new("init")
                .about("Initialize a new Sylva workspace")
                .arg(
                    Arg::new("path")
                        .help("Path to initialize the workspace")
                        .value_name("PATH")
                        .default_value(".")
                )
        )
        .subcommand(
            Command::new("add")
                .about("Add an entry to the ledger")
                .arg(
                    Arg::new("data")
                        .help("Data to add to the ledger")
                        .value_name("DATA")
                        .required(true)
                )
                .arg(
                    Arg::new("message")
                        .short('m')
                        .long("message")
                        .help("Optional message for the entry")
                        .value_name("MESSAGE")
                )
        )
        .subcommand(
            Command::new("proof")
                .about("Generate a proof for an entry")
                .arg(
                    Arg::new("entry-id")
                        .help("ID of the entry to generate proof for")
                        .value_name("ENTRY_ID")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("status")
                .about("Show workspace status")
        )
        .subcommand(build_commit_command())
        .subcommand(build_info_command())
        .subcommand(build_history_command())
        .subcommand(build_list_command())
        .subcommand(build_export_command())
        .subcommand(build_prove_command())
        .subcommand(build_verify_command())
        .subcommand(build_migrate_command())
        .subcommand(build_optimize_command())
        .subcommand(build_compact_command())
        .subcommand(build_analyze_command())
        .subcommand(build_cleanup_command())
        .subcommand(build_visualize_command())
        .subcommand(build_debug_command())
        .subcommand(build_trace_command())
        .subcommand(
            Command::new("config")
                .about("Get or set configuration values")
                .subcommand(
                    Command::new("get")
                        .about("Get a configuration value")
                        .arg(
                            Arg::new("key")
                                .help("Configuration key to get")
                                .value_name("KEY")
                                .required(true)
                        )
                )
                .subcommand(
                    Command::new("set")
                        .about("Set a configuration value")
                        .arg(
                            Arg::new("key")
                                .help("Configuration key to set")
                                .value_name("KEY")
                                .required(true)
                        )
                        .arg(
                            Arg::new("value")
                                .help("Configuration value to set")
                                .value_name("VALUE")
                                .required(true)
                        )
                )
                .subcommand(
                    Command::new("list")
                        .about("List all configuration values")
                )
        )
        .get_matches();

    match matches.subcommand() {
        Some(("init", sub_matches)) => {
            let path = sub_matches.get_one::<String>("path").unwrap();
            match Workspace::initialize(std::path::Path::new(path)) {
                Ok(_) => println!("Initialized Sylva workspace at: {}", path),
                Err(e) => {
                    eprintln!("Error initializing workspace: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("add", sub_matches)) => {
            let data = sub_matches.get_one::<String>("data").unwrap();
            let message = sub_matches.get_one::<String>("message");

            match Workspace::find_workspace() {
                Ok(_workspace) => {
                    println!("Adding entry with data: {}", data);
                    if let Some(msg) = message {
                        println!("Message: {}", msg);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("proof", sub_matches)) => {
            let entry_id = sub_matches.get_one::<String>("entry-id").unwrap();

            match Workspace::find_workspace() {
                Ok(_workspace) => {
                    println!("Generating proof for entry: {}", entry_id);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("commit", sub_matches)) => match handle_commit_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("info", sub_matches)) => match handle_info_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("history", sub_matches)) => match handle_history_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("list", sub_matches)) => match handle_list_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("export", sub_matches)) => match handle_export_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("prove", sub_matches)) => match handle_prove_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("verify", sub_matches)) => match handle_verify_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("migrate", sub_matches)) => match handle_migrate_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("optimize", sub_matches)) => match handle_optimize_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("compact", sub_matches)) => match handle_compact_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("analyze", sub_matches)) => match handle_analyze_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("cleanup", sub_matches)) => match handle_cleanup_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("visualize", sub_matches)) => match handle_visualize_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("debug", sub_matches)) => match handle_debug_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("trace", sub_matches)) => match handle_trace_command(sub_matches) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("status", _)) => match Workspace::find_workspace() {
            Ok(workspace) => {
                let status = workspace.status();
                println!("{}", status.display());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Some(("config", sub_matches)) => match sub_matches.subcommand() {
            Some(("get", config_matches)) => {
                let key = config_matches.get_one::<String>("key").unwrap();
                match Workspace::find_workspace() {
                    Ok(workspace) => match workspace.get_config_value(key) {
                        Ok(value) => println!("{}", value),
                        Err(e) => {
                            eprintln!("Error getting config value: {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Some(("set", config_matches)) => {
                let key = config_matches.get_one::<String>("key").unwrap();
                let value = config_matches.get_one::<String>("value").unwrap();
                match Workspace::find_workspace() {
                    Ok(mut workspace) => match workspace.set_config_value(key, value) {
                        Ok(()) => println!("Set {} = {}", key, value),
                        Err(e) => {
                            eprintln!("Error setting config value: {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Some(("list", _)) => match Workspace::find_workspace() {
                Ok(workspace) => {
                    let config_keys = [
                        "default_hash",
                        "cache_size",
                        "compression_level",
                        "ledger_format",
                        "default_tree_type",
                    ];
                    println!("Configuration values:");
                    for key in &config_keys {
                        match workspace.get_config_value(key) {
                            Ok(value) => println!("  {} = {}", key, value),
                            Err(e) => eprintln!("  Error getting {}: {}", key, e),
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            },
            _ => {
                println!("Use 'sylva config --help' for usage information");
            }
        },
        _ => {
            println!("Use 'sylva --help' for usage information");
        }
    }

    Ok(())
}

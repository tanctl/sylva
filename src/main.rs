//! cli for sylva

use clap::{Parser, Subcommand};
use std::process;
use sylva::error::Result;
use sylva::workspace::{WorkspaceInitOptions, WorkspaceManager};

#[derive(Parser)]
#[command(
    name = "sylva",
    version = env!("CARGO_PKG_VERSION"),
    about = "A versioned ledger and proof system for verifiable data",
    long_about = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(default_value = ".")]
        path: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(long)]
        with_examples: bool,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Add {
        data: String,
        #[arg(short, long)]
        message: Option<String>,
    },
    Verify {
        target: String,
    },
    List {
        #[arg(short, long)]
        detailed: bool,
        #[arg(short, long)]
        limit: Option<usize>,
    },
    Show {
        id: String,
    },
    Proof {
        id: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    Export {
        #[arg(short, long, default_value = "json")]
        format: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    Import {
        input: String,
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    Status,
    Version,
}

#[derive(Subcommand)]
enum ConfigAction {
    Get { key: String },
    Set { key: String, value: String },
    List,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init {
            path,
            name,
            description,
            with_examples,
        } => {
            let options = WorkspaceInitOptions {
                name,
                description,
                config: None,
                with_examples,
            };

            let mut manager = WorkspaceManager::new();
            manager.init(&path, options)?;

            println!("✅ Initialized Sylva workspace at: {}", path);
            if with_examples {
                println!("📄 Created example files (README.md, .gitignore)");
            }
            println!("🚀 Run 'sylva status' to see workspace information");
            Ok(())
        }
        Commands::Config { action } => {
            let mut manager = WorkspaceManager::new();

            match action {
                ConfigAction::Get { key } => {
                    let value = manager.get_config(&key)?;
                    println!("{}", value);
                }
                ConfigAction::Set { key, value } => {
                    manager.set_config(&key, &value)?;
                    println!("✅ Set {} = {}", key, value);
                }
                ConfigAction::List => {
                    let config = manager.list_config()?;
                    println!("Configuration:");
                    for (key, value) in config {
                        println!("  {} = {}", key, value);
                    }
                }
            }
            Ok(())
        }
        Commands::Add { data, message } => {
            println!("Adding entry: {}", data);
            if let Some(msg) = message {
                println!("Message: {}", msg);
            }
            // todo: implement entry addition
            Ok(())
        }
        Commands::Verify { target } => {
            println!("Verifying: {}", target);
            // todo: implement verification
            Ok(())
        }
        Commands::List { detailed, limit } => {
            println!(
                "Listing entries (detailed: {}, limit: {:?})",
                detailed, limit
            );
            // todo: implement entry listing
            Ok(())
        }
        Commands::Show { id } => {
            println!("Showing entry: {}", id);
            // todo: implement entry display
            Ok(())
        }
        Commands::Proof { id, output } => {
            println!("Generating proof for: {}", id);
            if let Some(out) = output {
                println!("Output file: {}", out);
            }
            // todo: implement proof generation
            Ok(())
        }
        Commands::Export { format, output } => {
            println!("Exporting in {} format", format);
            if let Some(out) = output {
                println!("Output file: {}", out);
            }
            // todo: implement data export
            Ok(())
        }
        Commands::Import { input, format } => {
            println!("Importing {} in {} format", input, format);
            // todo: implement data import
            Ok(())
        }
        Commands::Status => {
            let mut manager = WorkspaceManager::new();
            let info = manager.status()?;

            println!("Workspace Status");
            println!("================");
            println!("Name: {}", info.name);
            println!("Path: {}", info.root.display());
            println!("ID: {}", info.id);

            if let Some(desc) = &info.description {
                println!("Description: {}", desc);
            }

            if !info.tags.is_empty() {
                println!("Tags: {}", info.tags.join(", "));
            }

            println!();
            println!("Content:");
            println!("  Ledgers: {}", info.ledger_count);
            println!("  Proofs: {}", info.proof_count);
            println!("  Snapshots: {}", info.snapshot_count);
            println!("  Config: {}", if info.has_config { "✅" } else { "❌" });

            let created = std::time::UNIX_EPOCH + std::time::Duration::from_secs(info.created_at);
            let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(info.modified_at);
            println!();
            println!("Timestamps:");
            println!("  Created: {:?}", created);
            println!("  Modified: {:?}", modified);

            if !info.issues.is_empty() {
                println!();
                println!("⚠️  Issues:");
                for issue in &info.issues {
                    println!("  - {}", issue);
                }
            }

            Ok(())
        }
        Commands::Version => {
            println!("Sylva {}", env!("CARGO_PKG_VERSION"));
            println!("{}", env!("CARGO_PKG_DESCRIPTION"));
            Ok(())
        }
    }
}

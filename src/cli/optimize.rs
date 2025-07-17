use crate::error::{Result, SylvaError};
use crate::storage::LedgerStorage;
use crate::tree::{TreeFactory, TreeStatistics, TreeType, TreeTypeDetector, UnifiedTree};
use crate::workspace::Workspace;
use clap::ArgMatches;
use comfy_table::{presets::UTF8_FULL, Table};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub workspace_path: PathBuf,
    pub total_trees: usize,
    pub optimized_trees: usize,
    pub total_storage_before: usize,
    pub total_storage_after: usize,
    pub space_savings: f64,
    pub optimization_time: f64,
    pub tree_reports: Vec<TreeOptimizationReport>,
    pub recommendations: Vec<OptimizationRecommendation>,
    pub storage_analysis: StorageAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeOptimizationReport {
    pub tree_name: String,
    pub tree_type: TreeType,
    pub original_size: usize,
    pub optimized_size: usize,
    pub nodes_removed: usize,
    pub redundant_data_removed: usize,
    pub space_savings: f64,
    pub optimization_time: f64,
    pub was_rebalanced: bool,
    pub before_stats: TreeStatistics,
    pub after_stats: TreeStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    pub recommendation_type: RecommendationType,
    pub tree_name: String,
    pub description: String,
    pub potential_savings: Option<f64>,
    pub priority: RecommendationPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    TreeMigration,
    Rebalancing,
    Compression,
    GarbageCollection,
    NodeCompaction,
    StorageCleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAnalysis {
    pub total_files: usize,
    pub total_size: usize,
    pub unused_files: Vec<String>,
    pub duplicate_files: Vec<(String, String)>,
    pub large_files: Vec<(String, usize)>,
    pub compression_opportunities: Vec<String>,
}

impl OptimizationReport {
    pub fn display(&self) -> String {
        let mut output = String::new();

        output.push_str("🔧 Tree Optimization Report\n");
        output.push_str("════════════════════════════════════════════════════════════════\n");
        output.push_str(&format!("Workspace: {}\n", self.workspace_path.display()));
        output.push_str(&format!("Total trees analyzed: {}\n", self.total_trees));
        output.push_str(&format!("Trees optimized: {}\n", self.optimized_trees));
        output.push_str(&format!(
            "Optimization time: {:.2}s\n",
            self.optimization_time
        ));
        output.push('\n');

        if self.total_storage_before > 0 {
            output.push_str("💾 Storage Summary\n");
            output.push_str("────────────────────────────────────────────────────────────────\n");
            output.push_str(&format!(
                "Storage before: {}\n",
                Self::format_bytes(self.total_storage_before)
            ));
            output.push_str(&format!(
                "Storage after:  {}\n",
                Self::format_bytes(self.total_storage_after)
            ));
            output.push_str(&format!(
                "Space saved:    {} ({:.1}%)\n",
                Self::format_bytes(self.total_storage_before - self.total_storage_after),
                self.space_savings
            ));
            output.push('\n');
        }

        if !self.tree_reports.is_empty() {
            output.push_str("📊 Tree Optimization Details\n");
            output.push_str("────────────────────────────────────────────────────────────────\n");

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header([
                "Tree Name",
                "Type",
                "Original Size",
                "Optimized Size",
                "Savings",
                "Nodes Removed",
                "Rebalanced",
                "Time (s)",
            ]);

            for report in &self.tree_reports {
                table.add_row(&[
                    report.tree_name.clone(),
                    report.tree_type.as_str().to_string(),
                    Self::format_bytes(report.original_size),
                    Self::format_bytes(report.optimized_size),
                    format!("{:.1}%", report.space_savings),
                    report.nodes_removed.to_string(),
                    if report.was_rebalanced { "✓" } else { "✗" }.to_string(),
                    format!("{:.2}", report.optimization_time),
                ]);
            }

            output.push_str(&table.to_string());
            output.push('\n');
        }

        if !self.recommendations.is_empty() {
            output.push_str("💡 Optimization Recommendations\n");
            output.push_str("────────────────────────────────────────────────────────────────\n");

            for rec in &self.recommendations {
                let priority_icon = match rec.priority {
                    RecommendationPriority::High => "🔴",
                    RecommendationPriority::Medium => "🟡",
                    RecommendationPriority::Low => "🟢",
                };

                output.push_str(&format!(
                    "{} {}: {}\n",
                    priority_icon, rec.tree_name, rec.description
                ));

                if let Some(savings) = rec.potential_savings {
                    output.push_str(&format!("   Potential savings: {:.1}%\n", savings));
                }
            }
            output.push('\n');
        }

        output.push_str("📁 Storage Analysis\n");
        output.push_str("────────────────────────────────────────────────────────────────\n");
        output.push_str(&format!(
            "Total files: {}\n",
            self.storage_analysis.total_files
        ));
        output.push_str(&format!(
            "Total size: {}\n",
            Self::format_bytes(self.storage_analysis.total_size)
        ));

        if !self.storage_analysis.unused_files.is_empty() {
            output.push_str(&format!(
                "Unused files: {} (can be cleaned up)\n",
                self.storage_analysis.unused_files.len()
            ));
        }

        if !self.storage_analysis.duplicate_files.is_empty() {
            output.push_str(&format!(
                "Duplicate files: {} pairs found\n",
                self.storage_analysis.duplicate_files.len()
            ));
        }

        if !self.storage_analysis.compression_opportunities.is_empty() {
            output.push_str(&format!(
                "Compression opportunities: {} files\n",
                self.storage_analysis.compression_opportunities.len()
            ));
        }

        output
    }

    fn format_bytes(bytes: usize) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }
}

pub struct OptimizationEngine {
    workspace: Workspace,
    _storage: LedgerStorage,
    _factory: TreeFactory,
    detector: TreeTypeDetector,
}

impl OptimizationEngine {
    pub fn new(workspace: Workspace) -> Result<Self> {
        let storage = LedgerStorage::new(&workspace)?;
        let factory = TreeFactory::new();
        let detector = TreeTypeDetector::new();

        Ok(Self {
            workspace,
            _storage: storage,
            _factory: factory,
            detector,
        })
    }

    pub fn optimize_workspace(&mut self, dry_run: bool) -> Result<OptimizationReport> {
        let start_time = Instant::now();
        let workspace_path = self.workspace.root_path().to_path_buf();

        let trees = self.discover_trees()?;
        let mut tree_reports = Vec::new();
        let mut recommendations = Vec::new();

        let mut total_storage_before = 0;
        let mut total_storage_after = 0;
        let mut optimized_trees = 0;

        for (tree_name, tree_path) in &trees {
            let _tree_start = Instant::now();

            let original_size = fs::metadata(tree_path)?.len() as usize;
            total_storage_before += original_size;

            match self.optimize_tree(tree_name, tree_path, dry_run) {
                Ok(Some(report)) => {
                    total_storage_after += report.optimized_size;
                    if report.space_savings > 0.0 {
                        optimized_trees += 1;
                    }
                    tree_reports.push(report);
                }
                Ok(None) => {
                    total_storage_after += original_size;
                }
                Err(e) => {
                    recommendations.push(OptimizationRecommendation {
                        recommendation_type: RecommendationType::StorageCleanup,
                        tree_name: tree_name.clone(),
                        description: format!("Failed to optimize: {}", e),
                        potential_savings: None,
                        priority: RecommendationPriority::Medium,
                    });
                    total_storage_after += original_size;
                }
            }
        }

        let storage_analysis = self.analyze_storage()?;
        self.generate_recommendations(&trees, &tree_reports, &mut recommendations)?;

        let optimization_time = start_time.elapsed().as_secs_f64();
        let space_savings = if total_storage_before > 0 {
            ((total_storage_before - total_storage_after) as f64 / total_storage_before as f64)
                * 100.0
        } else {
            0.0
        };

        Ok(OptimizationReport {
            workspace_path,
            total_trees: trees.len(),
            optimized_trees,
            total_storage_before,
            total_storage_after,
            space_savings,
            optimization_time,
            tree_reports,
            recommendations,
            storage_analysis,
        })
    }

    fn discover_trees(&self) -> Result<Vec<(String, PathBuf)>> {
        let mut trees = Vec::new();
        let ledgers_path = self.workspace.ledgers_path();

        if !ledgers_path.exists() {
            return Ok(trees);
        }

        let entries = fs::read_dir(&ledgers_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    if let Some(name_str) = file_name.to_str() {
                        if name_str.ends_with(".tree")
                            || name_str.ends_with(".json")
                            || name_str.ends_with(".bin")
                        {
                            let tree_name =
                                name_str.split('.').next().unwrap_or(name_str).to_string();
                            trees.push((tree_name, path));
                        }
                    }
                }
            }
        }

        Ok(trees)
    }

    fn optimize_tree(
        &mut self,
        tree_name: &str,
        tree_path: &PathBuf,
        dry_run: bool,
    ) -> Result<Option<TreeOptimizationReport>> {
        let start_time = Instant::now();
        let original_size = fs::metadata(tree_path)?.len() as usize;

        let detection_result = self.detector.detect_from_file(tree_path)?;
        if !detection_result.is_reliable {
            return Ok(None);
        }

        let tree_type = detection_result.detected_type.unwrap();
        let mut tree = self.load_tree(tree_path, tree_type)?;

        let before_stats = tree.statistics();
        let mut nodes_removed = 0;
        let mut redundant_data_removed = 0;
        let mut was_rebalanced = false;

        nodes_removed += self.compact_tree(&mut tree)?;
        redundant_data_removed += self.remove_redundant_data(&mut tree)?;

        if self.should_rebalance(&tree) {
            self.rebalance_tree(&mut tree)?;
            was_rebalanced = true;
        }

        let after_stats = tree.statistics();
        let optimized_size = if dry_run {
            self.estimate_optimized_size(&tree)?
        } else {
            self.save_optimized_tree(&tree, tree_path)?
        };

        let optimization_time = start_time.elapsed().as_secs_f64();
        let space_savings = if original_size > 0 {
            ((original_size - optimized_size) as f64 / original_size as f64) * 100.0
        } else {
            0.0
        };

        Ok(Some(TreeOptimizationReport {
            tree_name: tree_name.to_string(),
            tree_type,
            original_size,
            optimized_size,
            nodes_removed,
            redundant_data_removed,
            space_savings,
            optimization_time,
            was_rebalanced,
            before_stats,
            after_stats,
        }))
    }

    fn load_tree(&self, tree_path: &PathBuf, tree_type: TreeType) -> Result<UnifiedTree> {
        let data = fs::read(tree_path)?;

        if let Ok(export_data) = bincode::deserialize::<crate::tree::TreeExportData>(&data) {
            let mut tree = UnifiedTree::new(tree_type);
            tree.import_from_migration(export_data)?;
            Ok(tree)
        } else {
            Err(SylvaError::InvalidInput {
                message: format!("Failed to load tree from {}", tree_path.display()),
            })
        }
    }

    fn compact_tree(&self, tree: &mut UnifiedTree) -> Result<usize> {
        let before_count = tree.entry_count();
        tree.compact()?;
        let after_count = tree.entry_count();
        Ok(before_count.saturating_sub(after_count))
    }

    fn remove_redundant_data(&self, tree: &mut UnifiedTree) -> Result<usize> {
        let before_size = tree.memory_usage().total_bytes;
        tree.remove_redundant_data()?;
        let after_size = tree.memory_usage().total_bytes;
        Ok(before_size.saturating_sub(after_size))
    }

    fn should_rebalance(&self, tree: &UnifiedTree) -> bool {
        let stats = tree.statistics();

        if stats.entry_count < 100 {
            return false;
        }

        let efficiency = stats.memory_usage.efficiency();
        efficiency < 0.7
    }

    fn rebalance_tree(&self, tree: &mut UnifiedTree) -> Result<()> {
        tree.rebalance()
    }

    fn estimate_optimized_size(&self, tree: &UnifiedTree) -> Result<usize> {
        let export_data = tree.export_for_migration(tree.tree_type())?;
        let serialized = bincode::serialize(&export_data)?;
        Ok(serialized.len())
    }

    fn save_optimized_tree(&self, tree: &UnifiedTree, original_path: &PathBuf) -> Result<usize> {
        let export_data = tree.export_for_migration(tree.tree_type())?;
        let serialized = bincode::serialize(&export_data)?;

        let backup_path = original_path.with_extension("backup");
        fs::rename(original_path, &backup_path)?;

        fs::write(original_path, &serialized)?;

        fs::remove_file(&backup_path)?;

        Ok(serialized.len())
    }

    pub fn analyze_storage(&self) -> Result<StorageAnalysis> {
        let ledgers_path = self.workspace.ledgers_path();
        let mut total_files = 0;
        let mut total_size = 0;
        let mut unused_files = Vec::new();
        let mut duplicate_files = Vec::new();
        let mut large_files = Vec::new();
        let mut compression_opportunities = Vec::new();
        let mut file_hashes: HashMap<String, Vec<String>> = HashMap::new();

        if !ledgers_path.exists() {
            return Ok(StorageAnalysis {
                total_files: 0,
                total_size: 0,
                unused_files,
                duplicate_files,
                large_files,
                compression_opportunities,
            });
        }

        let entries = fs::read_dir(&ledgers_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                total_files += 1;
                let metadata = fs::metadata(&path)?;
                let file_size = metadata.len() as usize;
                total_size += file_size;

                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                if file_size > 10 * 1024 * 1024 {
                    large_files.push((file_name.clone(), file_size));
                }

                if file_name.ends_with(".json") && file_size > 1024 {
                    compression_opportunities.push(file_name.clone());
                }

                if file_name.contains(".backup") || file_name.contains(".tmp") {
                    unused_files.push(file_name.clone());
                }

                let file_hash = self.calculate_file_hash(&path)?;
                file_hashes.entry(file_hash).or_default().push(file_name);
            }
        }

        for (_, files) in file_hashes {
            if files.len() > 1 {
                for i in 0..files.len() {
                    for j in i + 1..files.len() {
                        duplicate_files.push((files[i].clone(), files[j].clone()));
                    }
                }
            }
        }

        large_files.sort_by(|a, b| b.1.cmp(&a.1));
        large_files.truncate(10);

        Ok(StorageAnalysis {
            total_files,
            total_size,
            unused_files,
            duplicate_files,
            large_files,
            compression_opportunities,
        })
    }

    fn calculate_file_hash(&self, path: &PathBuf) -> Result<String> {
        use crate::hash::{Blake3Hasher, Hash};

        let data = fs::read(path)?;
        let hasher = Blake3Hasher::new();
        let hash = hasher.hash_bytes(&data)?;
        Ok(hash.to_string())
    }

    fn generate_recommendations(
        &self,
        trees: &[(String, PathBuf)],
        tree_reports: &[TreeOptimizationReport],
        recommendations: &mut Vec<OptimizationRecommendation>,
    ) -> Result<()> {
        for (tree_name, _) in trees {
            if let Some(report) = tree_reports.iter().find(|r| r.tree_name == *tree_name) {
                if report.space_savings < 5.0 && report.after_stats.memory_usage.efficiency() < 0.5
                {
                    recommendations.push(OptimizationRecommendation {
                        recommendation_type: RecommendationType::TreeMigration,
                        tree_name: tree_name.clone(),
                        description: "Consider migrating to a more efficient tree type".to_string(),
                        potential_savings: Some(30.0),
                        priority: RecommendationPriority::Medium,
                    });
                }

                if report.nodes_removed > 0 {
                    recommendations.push(OptimizationRecommendation {
                        recommendation_type: RecommendationType::GarbageCollection,
                        tree_name: tree_name.clone(),
                        description: "Regular garbage collection recommended".to_string(),
                        potential_savings: Some(report.space_savings),
                        priority: RecommendationPriority::Low,
                    });
                }
            }
        }

        Ok(())
    }
}

pub fn handle_optimize_command(matches: &ArgMatches) -> Result<()> {
    let workspace = Workspace::find_workspace()?;
    let mut engine = OptimizationEngine::new(workspace.clone())?;

    let dry_run = matches.get_flag("dry-run");
    let verbose = matches.get_flag("verbose");

    if dry_run {
        println!("🔍 Running optimization analysis (dry run)...");
    } else {
        println!("🔧 Starting workspace optimization...");
    }

    let report = engine.optimize_workspace(dry_run)?;

    if verbose || dry_run {
        println!("{}", report.display());
    } else {
        println!(
            "✓ Optimization completed in {:.2}s",
            report.optimization_time
        );
        println!("  Trees analyzed: {}", report.total_trees);
        println!("  Trees optimized: {}", report.optimized_trees);
        println!("  Space saved: {:.1}%", report.space_savings);
    }

    if !dry_run && report.optimized_trees > 0 {
        println!("\n💡 Run 'sylva optimize --dry-run' to preview optimizations before applying");
    }

    Ok(())
}

pub fn handle_compact_command(matches: &ArgMatches) -> Result<()> {
    let tree_name = matches.get_one::<String>("tree").unwrap();
    let dry_run = matches.get_flag("dry-run");

    println!("🗜️  Compacting tree '{}'...", tree_name);

    let workspace = Workspace::find_workspace()?;
    let mut engine = OptimizationEngine::new(workspace.clone())?;

    let trees = engine.discover_trees()?;
    let tree_entry = trees
        .iter()
        .find(|(name, _)| name == tree_name)
        .ok_or_else(|| SylvaError::InvalidInput {
            message: format!("Tree '{}' not found", tree_name),
        })?;

    if let Some(report) = engine.optimize_tree(&tree_entry.0, &tree_entry.1, dry_run)? {
        println!("✓ Compaction completed:");
        println!("  Nodes removed: {}", report.nodes_removed);
        println!("  Space saved: {:.1}%", report.space_savings);
        println!("  Time taken: {:.2}s", report.optimization_time);
    } else {
        println!("⚠️  No optimization needed for tree '{}'", tree_name);
    }

    Ok(())
}

pub fn handle_analyze_command(_matches: &ArgMatches) -> Result<()> {
    let workspace = Workspace::find_workspace()?;
    let storage = LedgerStorage::new(&workspace)?;

    println!("📊 Analyzing workspace storage and performance...");

    let compression_report = storage.generate_compression_report()?;
    println!("{}", compression_report.display());

    let engine = OptimizationEngine::new(workspace.clone())?;
    let storage_analysis = engine.analyze_storage()?;

    println!("📁 Storage File Analysis");
    println!("════════════════════════════════════════════════════════════════");
    println!("Total files: {}", storage_analysis.total_files);
    println!(
        "Total size: {}",
        OptimizationReport::format_bytes(storage_analysis.total_size)
    );

    if !storage_analysis.unused_files.is_empty() {
        println!("\n🗑️  Unused files that can be cleaned up:");
        for file in &storage_analysis.unused_files {
            println!("  • {}", file);
        }
    }

    if !storage_analysis.duplicate_files.is_empty() {
        println!("\n🔗 Duplicate files detected:");
        for (file1, file2) in &storage_analysis.duplicate_files {
            println!("  • {} ↔ {}", file1, file2);
        }
    }

    if !storage_analysis.large_files.is_empty() {
        println!("\n📦 Largest files:");
        for (file, size) in &storage_analysis.large_files {
            println!("  • {} ({})", file, OptimizationReport::format_bytes(*size));
        }
    }

    Ok(())
}

pub fn handle_cleanup_command(matches: &ArgMatches) -> Result<()> {
    let force = matches.get_flag("force");
    let dry_run = matches.get_flag("dry-run");

    let workspace = Workspace::find_workspace()?;
    let engine = OptimizationEngine::new(workspace.clone())?;
    let storage_analysis = engine.analyze_storage()?;

    if dry_run {
        println!("🔍 Storage cleanup analysis (dry run):");
    } else {
        println!("🧹 Cleaning up workspace storage...");
    }

    let mut files_to_remove = Vec::new();
    let mut total_space_to_free = 0;

    for file in &storage_analysis.unused_files {
        let file_path = workspace.ledgers_path().join(file);
        if file_path.exists() {
            if let Ok(metadata) = fs::metadata(&file_path) {
                total_space_to_free += metadata.len() as usize;
                files_to_remove.push(file_path);
            }
        }
    }

    if files_to_remove.is_empty() {
        println!("✓ No cleanup needed - workspace is already clean");
        return Ok(());
    }

    println!("Files to remove: {}", files_to_remove.len());
    println!(
        "Space to free: {}",
        OptimizationReport::format_bytes(total_space_to_free)
    );

    if dry_run {
        println!("\nFiles that would be removed:");
        for path in &files_to_remove {
            println!("  • {}", path.display());
        }
        return Ok(());
    }

    if !force {
        print!("Proceed with cleanup? [y/N]: ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if !input.trim().to_lowercase().starts_with('y') {
            println!("Cleanup cancelled");
            return Ok(());
        }
    }

    let mut removed_count = 0;
    let mut removed_size = 0;

    for path in &files_to_remove {
        if let Ok(metadata) = fs::metadata(path) {
            if fs::remove_file(path).is_ok() {
                removed_count += 1;
                removed_size += metadata.len() as usize;
            }
        }
    }

    println!("✓ Cleanup completed:");
    println!("  Files removed: {}", removed_count);
    println!(
        "  Space freed: {}",
        OptimizationReport::format_bytes(removed_size)
    );

    Ok(())
}

use crate::error::{Result, SylvaError};
use crate::storage::LedgerStorage;
use crate::tree::{MerkleProof, Tree, TreeType, TreeTypeDetector, UnifiedTree};
use crate::workspace::Workspace;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationConfig {
    pub max_depth: Option<usize>,
    pub max_nodes: Option<usize>,
    pub show_hashes: bool,
    pub show_metadata: bool,
    pub compact_mode: bool,
    pub color_mode: bool,
}

impl Default for VisualizationConfig {
    fn default() -> Self {
        Self {
            max_depth: Some(8),
            max_nodes: Some(100),
            show_hashes: true,
            show_metadata: false,
            compact_mode: false,
            color_mode: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub id: String,
    pub label: String,
    pub hash: Option<String>,
    pub level: usize,
    pub node_type: NodeType,
    pub metadata: HashMap<String, String>,
    pub children: Vec<String>,
    pub is_proof_path: bool,
    pub position: Option<(f64, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Root,
    Internal,
    Leaf,
    ProofNode,
    SiblingNode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeVisualization {
    pub tree_type: TreeType,
    pub root_id: Option<String>,
    pub nodes: HashMap<String, TreeNode>,
    pub edges: Vec<TreeEdge>,
    pub statistics: VisualizationStatistics,
    pub config: VisualizationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEdge {
    pub from: String,
    pub to: String,
    pub label: Option<String>,
    pub edge_type: EdgeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    TreeEdge,
    ProofPath,
    SiblingPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationStatistics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub tree_height: usize,
    pub leaf_count: usize,
    pub pruned_nodes: usize,
}

pub struct TreeVisualizer {
    pub config: VisualizationConfig,
}

impl TreeVisualizer {
    pub fn new(config: VisualizationConfig) -> Self {
        Self { config }
    }

    pub fn visualize_tree(&self, tree: &UnifiedTree) -> Result<TreeVisualization> {
        let tree_type = tree.tree_type();
        let mut nodes = HashMap::new();
        let mut edges = Vec::new();
        let mut node_counter = 0;

        let root_id = match tree_type {
            TreeType::Binary => {
                self.visualize_binary_tree(tree, &mut nodes, &mut edges, &mut node_counter)?
            }
            TreeType::Sparse => {
                self.visualize_sparse_tree(tree, &mut nodes, &mut edges, &mut node_counter)?
            }
            TreeType::Patricia => {
                self.visualize_patricia_tree(tree, &mut nodes, &mut edges, &mut node_counter)?
            }
        };

        let statistics = self.calculate_statistics(&nodes, &edges);

        Ok(TreeVisualization {
            tree_type,
            root_id,
            nodes,
            edges,
            statistics,
            config: self.config.clone(),
        })
    }

    fn visualize_binary_tree(
        &self,
        tree: &UnifiedTree,
        nodes: &mut HashMap<String, TreeNode>,
        edges: &mut Vec<TreeEdge>,
        node_counter: &mut usize,
    ) -> Result<Option<String>> {
        if let UnifiedTree::Binary(binary_tree) = tree {
            if binary_tree.is_empty() {
                return Ok(None);
            }

            let entries = binary_tree.get_entries();
            if entries.is_empty() {
                return Ok(None);
            }

            // Create a simplified binary tree visualization
            let root_id = format!("root_{}", *node_counter);
            *node_counter += 1;

            // Add root node
            nodes.insert(
                root_id.clone(),
                TreeNode {
                    id: root_id.clone(),
                    label: "Root".to_string(),
                    hash: binary_tree.root_hash().map(|h| h.to_hex()),
                    level: 0,
                    node_type: NodeType::Root,
                    metadata: HashMap::new(),
                    children: Vec::new(),
                    is_proof_path: false,
                    position: Some((0.0, 0.0)),
                },
            );

            // Add leaf nodes for entries (simplified view)
            let level = 1;

            // Group entries and create a balanced representation
            let max_entries = self.config.max_nodes.unwrap_or(100).min(entries.len());
            let entries_to_show = &entries[..max_entries];

            for (i, entry) in entries_to_show.iter().enumerate() {
                let node_id = format!("entry_{}", i);
                let mut metadata = HashMap::new();
                metadata.insert("version".to_string(), entry.version.to_string());
                metadata.insert("timestamp".to_string(), entry.timestamp.to_string());
                metadata.insert("data_size".to_string(), entry.data.len().to_string());

                nodes.insert(
                    node_id.clone(),
                    TreeNode {
                        id: node_id.clone(),
                        label: format!("Entry {}", i),
                        hash: Some(format!("{:.8}", entry.id)),
                        level,
                        node_type: NodeType::Leaf,
                        metadata: if self.config.show_metadata {
                            metadata
                        } else {
                            HashMap::new()
                        },
                        children: Vec::new(),
                        is_proof_path: false,
                        position: Some((i as f64, level as f64)),
                    },
                );

                // Connect to root (simplified)
                edges.push(TreeEdge {
                    from: root_id.clone(),
                    to: node_id,
                    label: None,
                    edge_type: EdgeType::TreeEdge,
                });
            }

            Ok(Some(root_id))
        } else {
            Err(SylvaError::InvalidInput {
                message: "Not a binary tree".to_string(),
            })
        }
    }

    fn visualize_sparse_tree(
        &self,
        tree: &UnifiedTree,
        nodes: &mut HashMap<String, TreeNode>,
        edges: &mut Vec<TreeEdge>,
        node_counter: &mut usize,
    ) -> Result<Option<String>> {
        if let UnifiedTree::Sparse(sparse_tree) = tree {
            if sparse_tree.is_empty() {
                return Ok(None);
            }

            let root_id = format!("sparse_root_{}", *node_counter);
            *node_counter += 1;

            nodes.insert(
                root_id.clone(),
                TreeNode {
                    id: root_id.clone(),
                    label: "Sparse Root".to_string(),
                    hash: Some(sparse_tree.root_hash().to_hex()),
                    level: 0,
                    node_type: NodeType::Root,
                    metadata: HashMap::new(),
                    children: Vec::new(),
                    is_proof_path: false,
                    position: Some((0.0, 0.0)),
                },
            );

            // For sparse trees, we'll create a simplified view showing the key-value pairs
            let entries = sparse_tree.entries();
            let max_entries = self.config.max_nodes.unwrap_or(50).min(entries.len());

            for (i, (key, value)) in entries.iter().take(max_entries).enumerate() {
                let node_id = format!("sparse_entry_{}", i);
                let mut metadata = HashMap::new();
                metadata.insert("key_size".to_string(), key.as_bytes().len().to_string());
                metadata.insert("value_size".to_string(), value.len().to_string());

                nodes.insert(
                    node_id.clone(),
                    TreeNode {
                        id: node_id.clone(),
                        label: format!("K-V {}", i),
                        hash: Some(format!(
                            "{:.8}",
                            hex::encode(&key.as_bytes()[..8.min(key.as_bytes().len())])
                        )),
                        level: 1,
                        node_type: NodeType::Leaf,
                        metadata: if self.config.show_metadata {
                            metadata
                        } else {
                            HashMap::new()
                        },
                        children: Vec::new(),
                        is_proof_path: false,
                        position: Some((i as f64, 1.0)),
                    },
                );

                edges.push(TreeEdge {
                    from: root_id.clone(),
                    to: node_id,
                    label: None,
                    edge_type: EdgeType::TreeEdge,
                });
            }

            Ok(Some(root_id))
        } else {
            Err(SylvaError::InvalidInput {
                message: "Not a sparse tree".to_string(),
            })
        }
    }

    fn visualize_patricia_tree(
        &self,
        tree: &UnifiedTree,
        nodes: &mut HashMap<String, TreeNode>,
        edges: &mut Vec<TreeEdge>,
        node_counter: &mut usize,
    ) -> Result<Option<String>> {
        if let UnifiedTree::Patricia(patricia_tree) = tree {
            if patricia_tree.is_empty() {
                return Ok(None);
            }

            let root_id = format!("patricia_root_{}", *node_counter);
            *node_counter += 1;

            nodes.insert(
                root_id.clone(),
                TreeNode {
                    id: root_id.clone(),
                    label: "Patricia Root".to_string(),
                    hash: patricia_tree.root_hash().map(|h| h.to_hex()),
                    level: 0,
                    node_type: NodeType::Root,
                    metadata: HashMap::new(),
                    children: Vec::new(),
                    is_proof_path: false,
                    position: Some((0.0, 0.0)),
                },
            );

            // For Patricia tries, show the key-value pairs
            let entries: Vec<_> = patricia_tree.iter().collect();
            let max_entries = self.config.max_nodes.unwrap_or(50).min(entries.len());

            for (i, (key, value)) in entries.iter().take(max_entries).enumerate() {
                let node_id = format!("patricia_entry_{}", i);
                let mut metadata = HashMap::new();
                metadata.insert("key_size".to_string(), key.len().to_string());
                metadata.insert("value_size".to_string(), value.len().to_string());

                let key_preview = if key.len() > 16 {
                    format!("{}...", hex::encode(&key[..8]))
                } else {
                    hex::encode(key)
                };

                nodes.insert(
                    node_id.clone(),
                    TreeNode {
                        id: node_id.clone(),
                        label: format!("Key {}", i),
                        hash: Some(key_preview),
                        level: 1,
                        node_type: NodeType::Leaf,
                        metadata: if self.config.show_metadata {
                            metadata
                        } else {
                            HashMap::new()
                        },
                        children: Vec::new(),
                        is_proof_path: false,
                        position: Some((i as f64, 1.0)),
                    },
                );

                edges.push(TreeEdge {
                    from: root_id.clone(),
                    to: node_id,
                    label: Some(format!("key_{}", i)),
                    edge_type: EdgeType::TreeEdge,
                });
            }

            Ok(Some(root_id))
        } else {
            Err(SylvaError::InvalidInput {
                message: "Not a Patricia tree".to_string(),
            })
        }
    }

    fn calculate_statistics(
        &self,
        nodes: &HashMap<String, TreeNode>,
        edges: &[TreeEdge],
    ) -> VisualizationStatistics {
        let total_nodes = nodes.len();
        let total_edges = edges.len();
        let tree_height = nodes.values().map(|n| n.level).max().unwrap_or(0);
        let leaf_count = nodes
            .values()
            .filter(|n| matches!(n.node_type, NodeType::Leaf))
            .count();
        let pruned_nodes = 0; // Would be calculated based on pruning logic

        VisualizationStatistics {
            total_nodes,
            total_edges,
            tree_height,
            leaf_count,
            pruned_nodes,
        }
    }

    pub fn visualize_proof_path(
        &self,
        proof: &MerkleProof,
        tree: &UnifiedTree,
    ) -> Result<TreeVisualization> {
        let mut visualization = self.visualize_tree(tree)?;

        // Mark proof path nodes
        let mut proof_node_ids = Vec::new();

        // Add proof path visualization
        for (i, element) in proof.path.iter().enumerate() {
            let proof_node_id = format!("proof_node_{}", i);
            proof_node_ids.push(proof_node_id.clone());

            visualization.nodes.insert(
                proof_node_id.clone(),
                TreeNode {
                    id: proof_node_id.clone(),
                    label: format!("Proof {}", i),
                    hash: Some(element.hash.to_string()),
                    level: i + 1,
                    node_type: NodeType::ProofNode,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("is_left".to_string(), element.is_left.to_string());
                        meta.insert("proof_step".to_string(), i.to_string());
                        meta
                    },
                    children: Vec::new(),
                    is_proof_path: true,
                    position: Some((100.0 + i as f64, i as f64)),
                },
            );
        }

        // Connect proof path
        for window in proof_node_ids.windows(2) {
            visualization.edges.push(TreeEdge {
                from: window[0].clone(),
                to: window[1].clone(),
                label: Some("proof".to_string()),
                edge_type: EdgeType::ProofPath,
            });
        }

        // Mark nodes in the original tree that are part of the proof path
        for node in visualization.nodes.values_mut() {
            if proof
                .path
                .iter()
                .any(|p| node.hash.as_ref() == Some(&p.hash.to_string()))
            {
                node.is_proof_path = true;
            }
        }

        Ok(visualization)
    }
}

pub struct ASCIIRenderer;

impl ASCIIRenderer {
    pub fn render(&self, visualization: &TreeVisualization) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Tree Visualization ({:?})\n",
            visualization.tree_type
        ));
        output.push_str("═══════════════════════════════════════════════════════════════\n");

        if let Some(root_id) = &visualization.root_id {
            Self::render_node_recursive(
                &visualization.nodes,
                &visualization.edges,
                root_id,
                &mut output,
                0,
                "",
                true,
                &visualization.config,
            );
        } else {
            output.push_str("Empty tree\n");
        }

        output.push_str("\nStatistics:\n");
        output.push_str(&format!(
            "  Total nodes: {}\n",
            visualization.statistics.total_nodes
        ));
        output.push_str(&format!(
            "  Total edges: {}\n",
            visualization.statistics.total_edges
        ));
        output.push_str(&format!(
            "  Tree height: {}\n",
            visualization.statistics.tree_height
        ));
        output.push_str(&format!(
            "  Leaf count: {}\n",
            visualization.statistics.leaf_count
        ));

        output
    }

    #[allow(clippy::too_many_arguments)]
    fn render_node_recursive(
        nodes: &HashMap<String, TreeNode>,
        edges: &[TreeEdge],
        node_id: &str,
        output: &mut String,
        depth: usize,
        prefix: &str,
        is_last: bool,
        config: &VisualizationConfig,
    ) {
        if let Some(max_depth) = config.max_depth {
            if depth > max_depth {
                output.push_str(&format!("{}├─ ...\n", prefix));
                return;
            }
        }

        if let Some(node) = nodes.get(node_id) {
            let connector = if is_last { "└─ " } else { "├─ " };
            let node_symbol = match node.node_type {
                NodeType::Root => "🌳",
                NodeType::Internal => "🔀",
                NodeType::Leaf => "🍃",
                NodeType::ProofNode => "🔍",
                NodeType::SiblingNode => "🔗",
            };

            let color_start = if config.color_mode && node.is_proof_path {
                "\x1b[93m" // Yellow for proof path
            } else {
                ""
            };
            let color_end = if config.color_mode && node.is_proof_path {
                "\x1b[0m" // Reset
            } else {
                ""
            };

            output.push_str(&format!(
                "{}{}{}{} {}{}\n",
                prefix, connector, color_start, node_symbol, node.label, color_end
            ));

            if config.show_hashes {
                if let Some(hash) = &node.hash {
                    let hash_display = if hash.len() > 16 {
                        format!("{}...", &hash[..16])
                    } else {
                        hash.clone()
                    };
                    let extension = if is_last { "    " } else { "│   " };
                    output.push_str(&format!("{}{}📋 {}\n", prefix, extension, hash_display));
                }
            }

            if config.show_metadata && !node.metadata.is_empty() {
                let extension = if is_last { "    " } else { "│   " };
                for (key, value) in &node.metadata {
                    output.push_str(&format!("{}{}ℹ️  {}: {}\n", prefix, extension, key, value));
                }
            }

            // Find children
            let mut children: Vec<_> = edges
                .iter()
                .filter(|e| e.from == *node_id)
                .map(|e| e.to.clone())
                .collect();
            children.sort(); // For consistent ordering

            // Render children
            for (i, child_id) in children.iter().enumerate() {
                let is_last_child = i == children.len() - 1;
                let new_prefix = if is_last {
                    format!("{}    ", prefix)
                } else {
                    format!("{}│   ", prefix)
                };

                Self::render_node_recursive(
                    nodes,
                    edges,
                    child_id,
                    output,
                    depth + 1,
                    &new_prefix,
                    is_last_child,
                    config,
                );
            }
        }
    }
}

pub struct DOTRenderer;

impl DOTRenderer {
    pub fn render(&self, visualization: &TreeVisualization) -> String {
        let mut output = String::new();

        output.push_str("digraph tree {\n");
        output.push_str("    rankdir=TB;\n");
        output.push_str("    node [shape=box, style=rounded];\n");
        output.push_str("    edge [fontsize=10];\n");
        output.push('\n');

        // Add nodes
        for node in visualization.nodes.values() {
            let color = match node.node_type {
                NodeType::Root => "lightblue",
                NodeType::Internal => "lightgray",
                NodeType::Leaf => "lightgreen",
                NodeType::ProofNode => "yellow",
                NodeType::SiblingNode => "orange",
            };

            let style = if node.is_proof_path {
                "filled,bold"
            } else {
                "filled"
            };

            let label = if visualization.config.show_hashes && node.hash.is_some() {
                format!("{}\\n{}", node.label, node.hash.as_ref().unwrap())
            } else {
                node.label.clone()
            };

            output.push_str(&format!(
                "    \"{}\" [label=\"{}\", fillcolor={}, style={}];\n",
                node.id, label, color, style
            ));
        }

        output.push('\n');

        // Add edges
        for edge in &visualization.edges {
            let edge_style = match edge.edge_type {
                EdgeType::TreeEdge => "solid",
                EdgeType::ProofPath => "bold",
                EdgeType::SiblingPath => "dashed",
            };

            let color = match edge.edge_type {
                EdgeType::TreeEdge => "black",
                EdgeType::ProofPath => "red",
                EdgeType::SiblingPath => "blue",
            };

            let label = edge
                .label
                .as_ref()
                .map(|l| format!(" [label=\"{}\"]", l))
                .unwrap_or_default();

            output.push_str(&format!(
                "    \"{}\" -> \"{}\" [style={}, color={}{}];\n",
                edge.from, edge.to, edge_style, color, label
            ));
        }

        output.push_str("}\n");
        output
    }
}

pub struct JSONRenderer;

impl JSONRenderer {
    pub fn render(&self, visualization: &TreeVisualization) -> Result<String> {
        serde_json::to_string_pretty(visualization).map_err(|e| SylvaError::InvalidInput {
            message: format!("JSON serialization failed: {}", e),
        })
    }
}

pub struct DebuggingUtilities;

impl DebuggingUtilities {
    pub fn analyze_tree_structure(tree: &UnifiedTree) -> TreeStructureAnalysis {
        let _stats = tree.statistics();
        let memory_usage = tree.memory_usage();

        TreeStructureAnalysis {
            tree_type: tree.tree_type(),
            entry_count: tree.entry_count(),
            tree_height: tree.height(),
            memory_efficiency: memory_usage.efficiency(),
            total_memory: memory_usage.total_bytes,
            is_empty: tree.is_empty(),
            is_valid: tree.validate().unwrap_or(false),
            balance_factor: Self::calculate_balance_factor(tree),
            depth_analysis: Self::analyze_depth_distribution(tree),
        }
    }

    fn calculate_balance_factor(tree: &UnifiedTree) -> f64 {
        // Simplified balance factor calculation
        let height = tree.height() as f64;
        let entry_count = tree.entry_count() as f64;

        if entry_count == 0.0 {
            return 1.0;
        }

        let optimal_height = entry_count.log2();
        if optimal_height == 0.0 {
            1.0
        } else {
            optimal_height / height.max(1.0)
        }
    }

    fn analyze_depth_distribution(tree: &UnifiedTree) -> DepthAnalysis {
        // Simplified depth analysis
        DepthAnalysis {
            min_depth: 0,
            max_depth: tree.height(),
            average_depth: tree.height() as f64 / 2.0,
            depth_variance: 0.0, // Would need actual tree traversal to calculate
        }
    }

    pub fn find_proof_path_issues(proof: &MerkleProof, tree: &UnifiedTree) -> Vec<ProofIssue> {
        let mut issues = Vec::new();

        // Check if proof verification works
        match tree {
            UnifiedTree::Binary(binary_tree) => {
                if let Some(entry) = binary_tree
                    .get_entries()
                    .iter()
                    .find(|e| e.id == proof.entry_id)
                {
                    if let Err(e) = proof.verify(entry) {
                        issues.push(ProofIssue {
                            issue_type: ProofIssueType::VerificationFailed,
                            description: format!("Proof verification failed: {}", e),
                            severity: IssueSeverity::High,
                        });
                    }
                } else {
                    issues.push(ProofIssue {
                        issue_type: ProofIssueType::EntryNotFound,
                        description: "Entry referenced in proof not found in tree".to_string(),
                        severity: IssueSeverity::High,
                    });
                }
            }
            _ => {
                issues.push(ProofIssue {
                    issue_type: ProofIssueType::UnsupportedTreeType,
                    description: "Proof verification only supported for binary trees".to_string(),
                    severity: IssueSeverity::Medium,
                });
            }
        }

        // Check proof path length
        if proof.path.is_empty() {
            issues.push(ProofIssue {
                issue_type: ProofIssueType::EmptyProofPath,
                description: "Proof path is empty".to_string(),
                severity: IssueSeverity::High,
            });
        }

        issues
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeStructureAnalysis {
    pub tree_type: TreeType,
    pub entry_count: usize,
    pub tree_height: usize,
    pub memory_efficiency: f64,
    pub total_memory: usize,
    pub is_empty: bool,
    pub is_valid: bool,
    pub balance_factor: f64,
    pub depth_analysis: DepthAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepthAnalysis {
    pub min_depth: usize,
    pub max_depth: usize,
    pub average_depth: f64,
    pub depth_variance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofIssue {
    pub issue_type: ProofIssueType,
    pub description: String,
    pub severity: IssueSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofIssueType {
    VerificationFailed,
    EntryNotFound,
    UnsupportedTreeType,
    EmptyProofPath,
    InvalidHashChain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

// CLI Command Handlers

pub fn handle_visualize_command(matches: &ArgMatches) -> Result<()> {
    let tree_name = matches.get_one::<String>("tree").unwrap();
    let default_format = "ascii".to_string();
    let format = matches
        .get_one::<String>("format")
        .unwrap_or(&default_format);
    let output_file = matches.get_one::<String>("output");
    let max_depth = matches
        .get_one::<String>("max-depth")
        .and_then(|s| s.parse().ok());
    let max_nodes = matches
        .get_one::<String>("max-nodes")
        .and_then(|s| s.parse().ok());

    let config = VisualizationConfig {
        max_depth,
        max_nodes,
        show_hashes: !matches.get_flag("no-hashes"),
        show_metadata: matches.get_flag("metadata"),
        color_mode: !matches.get_flag("no-color"),
        ..Default::default()
    };

    let workspace = Workspace::find_workspace()?;
    let tree = load_tree_by_name(&workspace, tree_name)?;

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree)?;

    let output_content = match format.as_str() {
        "ascii" => {
            let renderer = ASCIIRenderer;
            renderer.render(&visualization)
        }
        "dot" => {
            let renderer = DOTRenderer;
            renderer.render(&visualization)
        }
        "json" => {
            let renderer = JSONRenderer;
            renderer.render(&visualization)?
        }
        _ => {
            return Err(SylvaError::InvalidInput {
                message: format!("Unknown format: {}", format),
            })
        }
    };

    if let Some(output_path) = output_file {
        fs::write(output_path, &output_content)?;
        println!("Visualization saved to: {}", output_path);
    } else {
        println!("{}", output_content);
    }

    Ok(())
}

pub fn handle_debug_command(matches: &ArgMatches) -> Result<()> {
    let tree_name = matches.get_one::<String>("tree").unwrap();
    let workspace = Workspace::find_workspace()?;
    let tree = load_tree_by_name(&workspace, tree_name)?;

    let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

    println!("🔍 Tree Structure Analysis");
    println!("════════════════════════════════════════════════════════════════");
    println!("Tree type: {:?}", analysis.tree_type);
    println!("Entry count: {}", analysis.entry_count);
    println!("Tree height: {}", analysis.tree_height);
    println!(
        "Memory efficiency: {:.2}%",
        analysis.memory_efficiency * 100.0
    );
    println!("Total memory: {} bytes", analysis.total_memory);
    println!("Is empty: {}", analysis.is_empty);
    println!("Is valid: {}", analysis.is_valid);
    println!("Balance factor: {:.2}", analysis.balance_factor);
    println!("\nDepth Analysis:");
    println!("  Min depth: {}", analysis.depth_analysis.min_depth);
    println!("  Max depth: {}", analysis.depth_analysis.max_depth);
    println!(
        "  Average depth: {:.2}",
        analysis.depth_analysis.average_depth
    );
    println!(
        "  Depth variance: {:.2}",
        analysis.depth_analysis.depth_variance
    );

    if analysis.balance_factor < 0.5 {
        println!(
            "\n⚠️  Warning: Tree appears to be unbalanced (factor: {:.2})",
            analysis.balance_factor
        );
    }

    if !analysis.is_valid {
        println!("\n❌ Error: Tree structure validation failed!");
    }

    Ok(())
}

pub fn handle_proof_trace_command(matches: &ArgMatches) -> Result<()> {
    let tree_name = matches.get_one::<String>("tree").unwrap();
    let entry_id = matches.get_one::<String>("entry-id").unwrap();
    let default_format = "ascii".to_string();
    let format = matches
        .get_one::<String>("format")
        .unwrap_or(&default_format);

    let workspace = Workspace::find_workspace()?;
    let tree = load_tree_by_name(&workspace, tree_name)?;

    // Generate proof for the entry
    let entry_uuid = Uuid::parse_str(entry_id).map_err(|e| SylvaError::InvalidInput {
        message: format!("Invalid UUID: {}", e),
    })?;

    let proof =
        match &tree {
            UnifiedTree::Binary(binary_tree) => binary_tree
                .generate_proof(&entry_uuid)?
                .ok_or_else(|| SylvaError::InvalidInput {
                    message: "Entry not found".to_string(),
                })?,
            _ => {
                return Err(SylvaError::InvalidInput {
                    message: "Proof generation only supported for binary trees".to_string(),
                })
            }
        };

    println!("🔍 Proof Trace for Entry: {}", entry_id);
    println!("════════════════════════════════════════════════════════════════");

    // Check for issues
    let issues = DebuggingUtilities::find_proof_path_issues(&proof, &tree);
    if !issues.is_empty() {
        println!("⚠️  Issues found:");
        for issue in &issues {
            let severity_icon = match issue.severity {
                IssueSeverity::Critical => "🚨",
                IssueSeverity::High => "❌",
                IssueSeverity::Medium => "⚠️",
                IssueSeverity::Low => "ℹ️",
            };
            println!("  {} {}", severity_icon, issue.description);
        }
        println!();
    }

    // Visualize proof path
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);
    let proof_visualization = visualizer.visualize_proof_path(&proof, &tree)?;

    match format.as_str() {
        "ascii" => {
            let renderer = ASCIIRenderer;
            println!("{}", renderer.render(&proof_visualization));
        }
        "dot" => {
            let renderer = DOTRenderer;
            println!("{}", renderer.render(&proof_visualization));
        }
        "json" => {
            let renderer = JSONRenderer;
            println!("{}", renderer.render(&proof_visualization)?);
        }
        _ => {
            return Err(SylvaError::InvalidInput {
                message: format!("Unknown format: {}", format),
            })
        }
    }

    // Show proof details
    println!("\nProof Details:");
    println!("  Entry ID: {}", proof.entry_id);
    println!("  Entry hash: {}", proof.entry_hash);
    println!("  Root hash: {}", proof.root_hash);
    println!("  Proof path length: {}", proof.path.len());

    for (i, element) in proof.path.iter().enumerate() {
        println!(
            "  Step {}: {} ({})",
            i + 1,
            element.hash,
            if element.is_left { "left" } else { "right" }
        );
    }

    Ok(())
}

fn load_tree_by_name(workspace: &Workspace, tree_name: &str) -> Result<UnifiedTree> {
    let detector = TreeTypeDetector::new();

    // Try to find tree file with various extensions
    let possible_paths = [
        workspace.ledgers_path().join(format!("{}.tree", tree_name)),
        workspace
            .ledgers_path()
            .join(format!("{}_binary.tree", tree_name)),
        workspace
            .ledgers_path()
            .join(format!("{}_sparse.tree", tree_name)),
        workspace
            .ledgers_path()
            .join(format!("{}_patricia.tree", tree_name)),
    ];

    for path in &possible_paths {
        if path.exists() {
            let detection_result = detector.detect_from_file(path)?;
            if detection_result.is_reliable {
                let tree_type = detection_result.detected_type.unwrap();
                let data = fs::read(path)?;

                if let Ok(export_data) = bincode::deserialize::<crate::tree::TreeExportData>(&data)
                {
                    let mut tree = UnifiedTree::new(tree_type);
                    tree.import_from_migration(export_data)?;
                    return Ok(tree);
                }
            }
        }
    }

    // Try to load from ledger storage
    let storage = LedgerStorage::new(workspace)?;
    let ledgers = storage.list_ledgers()?;

    for ledger_metadata in ledgers {
        if ledger_metadata.description.as_ref() == Some(&tree_name.to_string()) {
            let serializable_ledger = storage.load_ledger(&ledger_metadata.id)?;

            // Create a tree from the ledger
            let mut tree = UnifiedTree::new(TreeType::Binary);
            for entry in serializable_ledger.ledger.get_entries() {
                tree.insert_ledger_entry(entry.clone())?;
            }
            return Ok(tree);
        }
    }

    Err(SylvaError::InvalidInput {
        message: format!("Tree '{}' not found", tree_name),
    })
}

use std::collections::HashMap;
use sylva::cli::visualize::{
    ASCIIRenderer, DOTRenderer, DebuggingUtilities, JSONRenderer, TreeVisualizer,
    VisualizationConfig,
};
use sylva::hash::{Blake3Hasher, Hash};
use sylva::ledger::Ledger;
use sylva::tree::{MerkleProof, ProofElement, Tree, TreeType, UnifiedTree};
use uuid::Uuid;

fn create_test_ledger(entry_count: usize) -> Ledger {
    let mut ledger = Ledger::new();

    for i in 0..entry_count {
        let data = format!("test data entry {}", i).into_bytes();
        ledger.add_entry(data).unwrap();

        if i % 3 == 0 {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "special".to_string());
            let special_data = format!("special entry {}", i).into_bytes();
            ledger
                .add_entry_with_metadata(special_data, metadata)
                .unwrap();
        }
    }

    ledger
}

fn create_test_tree(tree_type: TreeType, entry_count: usize) -> UnifiedTree {
    let mut tree = UnifiedTree::new(tree_type);
    let ledger = create_test_ledger(entry_count);

    for entry in ledger.get_entries() {
        tree.insert_ledger_entry(entry.clone()).unwrap();
    }

    tree
}

#[test]
fn test_visualization_config_default() {
    let config = VisualizationConfig::default();

    assert_eq!(config.max_depth, Some(8));
    assert_eq!(config.max_nodes, Some(100));
    assert!(config.show_hashes);
    assert!(!config.show_metadata);
    assert!(!config.compact_mode);
    assert!(config.color_mode);
}

#[test]
fn test_visualization_config_custom() {
    let mut config = VisualizationConfig::default();
    config.max_depth = Some(5);
    config.max_nodes = Some(50);
    config.show_metadata = true;
    config.color_mode = false;

    assert_eq!(config.max_depth, Some(5));
    assert_eq!(config.max_nodes, Some(50));
    assert!(config.show_metadata);
    assert!(!config.color_mode);
}

#[test]
fn test_tree_visualizer_creation() {
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config.clone());

    // Visualizer should be created successfully
    assert_eq!(visualizer.config.max_depth, config.max_depth);
    assert_eq!(visualizer.config.show_hashes, config.show_hashes);
}

#[test]
fn test_binary_tree_visualization() {
    let tree = create_test_tree(TreeType::Binary, 5);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    assert_eq!(visualization.tree_type, TreeType::Binary);
    assert!(visualization.root_id.is_some());
    assert!(!visualization.nodes.is_empty());
    assert!(!visualization.edges.is_empty());
    assert!(visualization.statistics.total_nodes > 0);
    assert_eq!(
        visualization.statistics.total_edges,
        visualization.edges.len()
    );
}

#[test]
fn test_sparse_tree_visualization() {
    let tree = create_test_tree(TreeType::Sparse, 5);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    assert_eq!(visualization.tree_type, TreeType::Sparse);
    assert!(visualization.root_id.is_some());
    assert!(!visualization.nodes.is_empty());
    assert_eq!(
        visualization.statistics.total_nodes,
        visualization.nodes.len()
    );
}

#[test]
fn test_patricia_tree_visualization() {
    let tree = create_test_tree(TreeType::Patricia, 5);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    assert_eq!(visualization.tree_type, TreeType::Patricia);
    assert!(visualization.root_id.is_some());
    assert!(!visualization.nodes.is_empty());
}

#[test]
fn test_empty_tree_visualization() {
    let tree = UnifiedTree::new(TreeType::Binary);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    assert_eq!(visualization.tree_type, TreeType::Binary);
    assert!(visualization.root_id.is_none());
    assert!(visualization.nodes.is_empty() || visualization.nodes.len() == 1); // May have root node
}

#[test]
fn test_visualization_with_limits() {
    let tree = create_test_tree(TreeType::Binary, 20);
    let mut config = VisualizationConfig::default();
    config.max_nodes = Some(5);
    config.max_depth = Some(2);

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree).unwrap();

    // Should respect the limits
    assert!(visualization.statistics.total_nodes <= 6); // 5 + root
}

#[test]
fn test_ascii_renderer() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = ASCIIRenderer;
    let output = renderer.render(&visualization);

    // Check that output contains expected elements
    assert!(output.contains("Tree Visualization"));
    assert!(output.contains("Binary"));
    assert!(output.contains("Statistics:"));
    assert!(output.contains("Total nodes:"));
    assert!(output.contains("🌳")); // Tree emoji for root
    assert!(output.contains("🍃")); // Leaf emoji for entries
}

#[test]
fn test_ascii_renderer_with_metadata() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let mut config = VisualizationConfig::default();
    config.show_metadata = true;

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = ASCIIRenderer;
    let output = renderer.render(&visualization);

    // Should contain metadata indicators
    assert!(output.contains("ℹ️")); // Info emoji for metadata
}

#[test]
fn test_ascii_renderer_no_hashes() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let mut config = VisualizationConfig::default();
    config.show_hashes = false;

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = ASCIIRenderer;
    let output = renderer.render(&visualization);

    // Should not contain hash indicators when disabled
    assert!(!output.contains("📋")); // Clipboard emoji for hashes
}

#[test]
fn test_dot_renderer() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = DOTRenderer;
    let output = renderer.render(&visualization);

    // Check DOT format structure
    assert!(output.contains("digraph tree {"));
    assert!(output.contains("rankdir=TB;"));
    assert!(output.contains("node ["));
    assert!(output.contains("edge ["));
    assert!(output.contains("}"));
    assert!(output.contains("fillcolor="));
    assert!(output.contains("->"));
}

#[test]
fn test_dot_renderer_with_proof_nodes() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let mut visualization = visualizer.visualize_tree(&tree).unwrap();

    // Add a proof node manually for testing
    visualization.nodes.insert(
        "proof_1".to_string(),
        sylva::cli::visualize::TreeNode {
            id: "proof_1".to_string(),
            label: "Proof Node".to_string(),
            hash: Some("proof_hash".to_string()),
            level: 1,
            node_type: sylva::cli::visualize::NodeType::ProofNode,
            metadata: HashMap::new(),
            children: Vec::new(),
            is_proof_path: true,
            position: Some((0.0, 1.0)),
        },
    );

    let renderer = DOTRenderer;
    let output = renderer.render(&visualization);

    // Should handle proof nodes with special styling
    assert!(output.contains("fillcolor=yellow")); // Proof nodes should be yellow
    assert!(
        output.contains("style=filled,bold")
            || output.contains("style=bold")
            || output.contains("style=filled")
    );
}

#[test]
fn test_json_renderer() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = JSONRenderer;
    let output = renderer.render(&visualization).unwrap();

    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert!(parsed["tree_type"].is_string());
    assert!(parsed["nodes"].is_object());
    assert!(parsed["edges"].is_array());
    assert!(parsed["statistics"].is_object());
    assert_eq!(parsed["tree_type"], "Binary");
}

#[test]
fn test_json_renderer_roundtrip() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let original_visualization = visualizer.visualize_tree(&tree).unwrap();
    let renderer = JSONRenderer;
    let json_output = renderer.render(&original_visualization).unwrap();

    // Parse back to ensure roundtrip works
    let parsed_visualization: sylva::cli::visualize::TreeVisualization =
        serde_json::from_str(&json_output).unwrap();

    assert_eq!(
        parsed_visualization.tree_type,
        original_visualization.tree_type
    );
    assert_eq!(
        parsed_visualization.nodes.len(),
        original_visualization.nodes.len()
    );
    assert_eq!(
        parsed_visualization.edges.len(),
        original_visualization.edges.len()
    );
}

#[test]
fn test_proof_path_visualization() {
    let tree = create_test_tree(TreeType::Binary, 5);

    if let UnifiedTree::Binary(binary_tree) = &tree {
        if let Some(entry) = binary_tree.get_entries().first() {
            if let Ok(Some(proof)) = binary_tree.generate_proof(&entry.id) {
                let config = VisualizationConfig::default();
                let visualizer = TreeVisualizer::new(config);

                let proof_visualization = visualizer.visualize_proof_path(&proof, &tree).unwrap();

                // Should have proof-specific elements
                assert!(proof_visualization.nodes.values().any(|n| n.is_proof_path));
                assert!(proof_visualization
                    .nodes
                    .values()
                    .any(|n| matches!(n.node_type, sylva::cli::visualize::NodeType::ProofNode)));
                assert!(proof_visualization
                    .edges
                    .iter()
                    .any(|e| matches!(e.edge_type, sylva::cli::visualize::EdgeType::ProofPath)));
            }
        }
    }
}

#[test]
fn test_debugging_utilities_structure_analysis() {
    let tree = create_test_tree(TreeType::Binary, 10);
    let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

    assert_eq!(analysis.tree_type, TreeType::Binary);
    assert!(analysis.entry_count > 0);
    assert!(analysis.total_memory > 0);
    assert!(analysis.memory_efficiency >= 0.0 && analysis.memory_efficiency <= 1.0);
    assert!(analysis.balance_factor >= 0.0);
    assert!(!analysis.is_empty);
}

#[test]
fn test_debugging_utilities_empty_tree() {
    let tree = UnifiedTree::new(TreeType::Binary);
    let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

    assert_eq!(analysis.tree_type, TreeType::Binary);
    assert_eq!(analysis.entry_count, 0);
    assert!(analysis.is_empty);
    assert_eq!(analysis.tree_height, 0);
}

#[test]
fn test_debugging_utilities_different_tree_types() {
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        let tree = create_test_tree(tree_type, 5);
        let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

        assert_eq!(analysis.tree_type, tree_type);
        assert!(analysis.entry_count > 0);
        assert!(!analysis.is_empty);
    }
}

#[test]
fn test_proof_issue_detection() {
    let tree = create_test_tree(TreeType::Binary, 5);

    if let UnifiedTree::Binary(binary_tree) = &tree {
        if let Some(entry) = binary_tree.get_entries().first() {
            if let Ok(Some(proof)) = binary_tree.generate_proof(&entry.id) {
                let issues = DebuggingUtilities::find_proof_path_issues(&proof, &tree);

                // For a valid proof, there should be no critical issues
                let critical_issues: Vec<_> = issues
                    .iter()
                    .filter(|issue| {
                        matches!(
                            issue.severity,
                            sylva::cli::visualize::IssueSeverity::Critical
                        )
                    })
                    .collect();

                assert!(critical_issues.is_empty());
            }
        }
    }
}

#[test]
fn test_proof_issue_detection_invalid_entry() {
    let tree = create_test_tree(TreeType::Binary, 5);

    // Create a proof for a non-existent entry
    let fake_entry_id = Uuid::new_v4();
    let hasher = Blake3Hasher::new();
    let fake_hash = hasher.hash_bytes(b"fake data").unwrap();

    let proof = MerkleProof {
        entry_id: fake_entry_id,
        entry_hash: fake_hash.clone(),
        path: vec![ProofElement {
            hash: fake_hash,
            is_left: true,
        }],
        root_hash: hasher.hash_bytes(b"fake root").unwrap(),
    };

    let issues = DebuggingUtilities::find_proof_path_issues(&proof, &tree);

    // Should detect that the entry is not found
    assert!(issues.iter().any(|issue| matches!(
        issue.issue_type,
        sylva::cli::visualize::ProofIssueType::EntryNotFound
    )));
}

#[test]
fn test_proof_issue_detection_empty_path() {
    let tree = create_test_tree(TreeType::Binary, 5);

    if let UnifiedTree::Binary(binary_tree) = &tree {
        if let Some(entry) = binary_tree.get_entries().first() {
            // Create a proof with empty path
            let hasher = Blake3Hasher::new();
            let proof = MerkleProof {
                entry_id: entry.id,
                entry_hash: hasher.hash_bytes(&entry.data).unwrap(),
                path: vec![], // Empty path
                root_hash: hasher.hash_bytes(b"fake root").unwrap(),
            };

            let issues = DebuggingUtilities::find_proof_path_issues(&proof, &tree);

            // Should detect empty proof path
            assert!(issues.iter().any(|issue| matches!(
                issue.issue_type,
                sylva::cli::visualize::ProofIssueType::EmptyProofPath
            )));
        }
    }
}

#[test]
fn test_proof_issue_detection_unsupported_tree() {
    let tree = create_test_tree(TreeType::Sparse, 5);

    // Create a dummy proof
    let hasher = Blake3Hasher::new();
    let fake_hash = hasher.hash_bytes(b"fake data").unwrap();
    let proof = MerkleProof {
        entry_id: Uuid::new_v4(),
        entry_hash: fake_hash.clone(),
        path: vec![ProofElement {
            hash: fake_hash,
            is_left: true,
        }],
        root_hash: hasher.hash_bytes(b"fake root").unwrap(),
    };

    let issues = DebuggingUtilities::find_proof_path_issues(&proof, &tree);

    // Should detect unsupported tree type
    assert!(issues.iter().any(|issue| matches!(
        issue.issue_type,
        sylva::cli::visualize::ProofIssueType::UnsupportedTreeType
    )));
}

#[test]
fn test_visualization_statistics_calculation() {
    let tree = create_test_tree(TreeType::Binary, 8);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();
    let stats = &visualization.statistics;

    assert_eq!(stats.total_nodes, visualization.nodes.len());
    assert_eq!(stats.total_edges, visualization.edges.len());
    assert!(stats.tree_height <= tree.height());

    let actual_leaf_count = visualization
        .nodes
        .values()
        .filter(|n| matches!(n.node_type, sylva::cli::visualize::NodeType::Leaf))
        .count();
    assert_eq!(stats.leaf_count, actual_leaf_count);
}

#[test]
fn test_node_positioning() {
    let tree = create_test_tree(TreeType::Binary, 5);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    // Check that nodes have position information
    let positioned_nodes = visualization
        .nodes
        .values()
        .filter(|n| n.position.is_some())
        .count();

    assert!(positioned_nodes > 0);

    // Root should be at (0, 0) if present
    if let Some(root_id) = &visualization.root_id {
        if let Some(root_node) = visualization.nodes.get(root_id) {
            assert_eq!(root_node.position, Some((0.0, 0.0)));
        }
    }
}

#[test]
fn test_edge_types() {
    let tree = create_test_tree(TreeType::Binary, 5);
    let config = VisualizationConfig::default();
    let visualizer = TreeVisualizer::new(config);

    let visualization = visualizer.visualize_tree(&tree).unwrap();

    // Regular tree should have TreeEdge types
    assert!(visualization
        .edges
        .iter()
        .all(|e| matches!(e.edge_type, sylva::cli::visualize::EdgeType::TreeEdge)));
}

#[test]
fn test_renderer_with_large_tree() {
    let tree = create_test_tree(TreeType::Binary, 50);
    let mut config = VisualizationConfig::default();
    config.max_nodes = Some(10); // Limit to prevent overwhelming output

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree).unwrap();

    // All renderers should handle limited tree gracefully
    let ascii_renderer = ASCIIRenderer;
    let ascii_output = ascii_renderer.render(&visualization);
    assert!(!ascii_output.is_empty());

    let dot_renderer = DOTRenderer;
    let dot_output = dot_renderer.render(&visualization);
    assert!(dot_output.contains("digraph tree"));

    let json_renderer = JSONRenderer;
    let json_output = json_renderer.render(&visualization).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&json_output).is_ok());
}

#[test]
fn test_visualization_metadata_handling() {
    let tree = create_test_tree(TreeType::Binary, 3);
    let mut config = VisualizationConfig::default();
    config.show_metadata = true;

    let visualizer = TreeVisualizer::new(config);
    let visualization = visualizer.visualize_tree(&tree).unwrap();

    // Some nodes should have metadata when enabled
    let nodes_with_metadata = visualization
        .nodes
        .values()
        .filter(|n| !n.metadata.is_empty())
        .count();

    assert!(nodes_with_metadata > 0);
}

#[test]
fn test_depth_analysis_calculation() {
    let tree = create_test_tree(TreeType::Binary, 10);
    let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

    let depth_analysis = &analysis.depth_analysis;

    assert!(depth_analysis.min_depth <= depth_analysis.max_depth);
    assert!(depth_analysis.average_depth >= depth_analysis.min_depth as f64);
    assert!(depth_analysis.average_depth <= depth_analysis.max_depth as f64);
    assert!(depth_analysis.depth_variance >= 0.0);
}

#[test]
fn test_balance_factor_calculation() {
    // Test with different tree sizes
    for size in [1, 5, 10, 20] {
        let tree = create_test_tree(TreeType::Binary, size);
        let analysis = DebuggingUtilities::analyze_tree_structure(&tree);

        // Balance factor should be between 0 and 1
        assert!(analysis.balance_factor >= 0.0);
        assert!(analysis.balance_factor <= 1.0);
    }
}

#[test]
fn test_visualization_config_serialization() {
    let config = VisualizationConfig {
        max_depth: Some(5),
        max_nodes: Some(25),
        show_hashes: false,
        show_metadata: true,
        compact_mode: true,
        color_mode: false,
    };

    // Should serialize and deserialize correctly
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: VisualizationConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.max_depth, deserialized.max_depth);
    assert_eq!(config.max_nodes, deserialized.max_nodes);
    assert_eq!(config.show_hashes, deserialized.show_hashes);
    assert_eq!(config.show_metadata, deserialized.show_metadata);
    assert_eq!(config.compact_mode, deserialized.compact_mode);
    assert_eq!(config.color_mode, deserialized.color_mode);
}

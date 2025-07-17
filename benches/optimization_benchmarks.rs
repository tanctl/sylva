use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use sylva::cli::optimize::OptimizationEngine;
use sylva::ledger::{Ledger, LedgerEntry};
use sylva::tree::{TreeFactory, TreeType, UnifiedTree};
use sylva::workspace::Workspace;
use tempfile::TempDir;

fn create_test_workspace() -> (TempDir, Workspace) {
    let temp_dir = TempDir::new().unwrap();
    let workspace = Workspace::init(temp_dir.path()).unwrap();
    (temp_dir, workspace)
}

fn create_test_ledger(entry_count: usize) -> Ledger {
    let mut ledger = Ledger::new();

    for i in 0..entry_count {
        let data = format!("test data entry {}", i).into_bytes();
        ledger.add_entry(data).unwrap();

        if i % 10 == 0 {
            let mut metadata = HashMap::new();
            metadata.insert("batch".to_string(), (i / 10).to_string());
            let metadata_data = format!("metadata entry {}", i).into_bytes();
            ledger
                .add_entry_with_metadata(metadata_data, metadata)
                .unwrap();
        }
    }

    ledger
}

fn create_unoptimized_tree(tree_type: TreeType, entry_count: usize) -> UnifiedTree {
    let mut tree = UnifiedTree::new(tree_type);
    let ledger = create_test_ledger(entry_count);

    for entry in ledger.get_entries() {
        tree.insert_ledger_entry(entry.clone()).unwrap();
    }

    // Simulate some inefficiency by adding and removing entries
    for i in 0..entry_count / 10 {
        let dummy_entry = LedgerEntry::new(format!("dummy {}", i).into_bytes(), 9999 + i as u64);
        tree.insert_ledger_entry(dummy_entry).unwrap();
    }

    tree
}

fn bench_tree_compaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_compaction");

    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        for size in [100, 1000, 5000].iter() {
            group.throughput(Throughput::Elements(*size as u64));

            group.bench_with_input(
                BenchmarkId::new(format!("{}_compact", tree_type.as_str()), size),
                size,
                |b, &size| {
                    b.iter_batched(
                        || create_unoptimized_tree(tree_type, size),
                        |mut tree| {
                            tree.compact().unwrap();
                            tree
                        },
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_tree_rebalancing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_rebalancing");

    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        for size in [100, 1000, 5000].iter() {
            group.throughput(Throughput::Elements(*size as u64));

            group.bench_with_input(
                BenchmarkId::new(format!("{}_rebalance", tree_type.as_str()), size),
                size,
                |b, &size| {
                    b.iter_batched(
                        || create_unoptimized_tree(tree_type, size),
                        |mut tree| {
                            tree.rebalance().unwrap();
                            tree
                        },
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_redundant_data_removal(c: &mut Criterion) {
    let mut group = c.benchmark_group("redundant_data_removal");

    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        for size in [100, 1000, 5000].iter() {
            group.throughput(Throughput::Elements(*size as u64));

            group.bench_with_input(
                BenchmarkId::new(format!("{}_remove_redundant", tree_type.as_str()), size),
                size,
                |b, &size| {
                    b.iter_batched(
                        || create_unoptimized_tree(tree_type, size),
                        |mut tree| {
                            tree.remove_redundant_data().unwrap();
                            tree
                        },
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_full_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_optimization");

    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        for size in [100, 1000, 5000].iter() {
            group.throughput(Throughput::Elements(*size as u64));

            group.bench_with_input(
                BenchmarkId::new(format!("{}_full_optimize", tree_type.as_str()), size),
                size,
                |b, &size| {
                    b.iter_batched(
                        || create_unoptimized_tree(tree_type, size),
                        |mut tree| {
                            tree.compact().unwrap();
                            tree.remove_redundant_data().unwrap();
                            tree.rebalance().unwrap();
                            tree
                        },
                        criterion::BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

fn bench_memory_usage_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage_comparison");

    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        for size in [1000, 5000].iter() {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_memory_before", tree_type.as_str()), size),
                size,
                |b, &size| {
                    let tree = create_unoptimized_tree(tree_type, size);
                    b.iter(|| {
                        let memory_usage = tree.memory_usage();
                        memory_usage.total_bytes
                    })
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("{}_memory_after", tree_type.as_str()), size),
                size,
                |b, &size| {
                    let mut tree = create_unoptimized_tree(tree_type, size);
                    tree.compact().unwrap();
                    tree.remove_redundant_data().unwrap();
                    tree.rebalance().unwrap();

                    b.iter(|| {
                        let memory_usage = tree.memory_usage();
                        memory_usage.total_bytes
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_workspace_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("workspace_optimization");
    group.sample_size(10); // Reduce sample size for expensive operations

    for tree_count in [5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::new("workspace_optimize", tree_count),
            tree_count,
            |b, &tree_count| {
                b.iter_batched(
                    || {
                        let (_temp_dir, workspace) = create_test_workspace();
                        let engine = OptimizationEngine::new(workspace).unwrap();

                        // Create some test trees (simulate by creating ledger files)
                        for _i in 0..tree_count {
                            let _ledger = create_test_ledger(100);
                            let _tree = UnifiedTree::new(TreeType::Binary);
                            // In a real scenario, these would be saved to the workspace
                        }

                        engine
                    },
                    |mut engine| {
                        engine.optimize_workspace(true).unwrap() // dry run for benchmark
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_tree_migration_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_migration_optimization");

    let _factory = TreeFactory::new();

    for size in [100, 1000].iter() {
        // Binary to Sparse migration
        group.bench_with_input(
            BenchmarkId::new("binary_to_sparse", size),
            size,
            |b, &size| {
                b.iter_batched(
                    || create_unoptimized_tree(TreeType::Binary, size),
                    |tree| tree.migrate_to(TreeType::Sparse).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        // Sparse to Patricia migration
        group.bench_with_input(
            BenchmarkId::new("sparse_to_patricia", size),
            size,
            |b, &size| {
                b.iter_batched(
                    || create_unoptimized_tree(TreeType::Sparse, size),
                    |tree| tree.migrate_to(TreeType::Patricia).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_optimization_effectiveness(c: &mut Criterion) {
    let mut group = c.benchmark_group("optimization_effectiveness");

    // Benchmark to measure actual space savings
    for tree_type in [TreeType::Binary, TreeType::Sparse, TreeType::Patricia] {
        group.bench_function(&format!("{}_space_savings", tree_type.as_str()), |b| {
            b.iter_batched(
                || create_unoptimized_tree(tree_type, 1000),
                |mut tree| {
                    let before_size = tree.memory_usage().total_bytes;

                    tree.compact().unwrap();
                    tree.remove_redundant_data().unwrap();
                    tree.rebalance().unwrap();

                    let after_size = tree.memory_usage().total_bytes;
                    let savings = ((before_size - after_size) as f64 / before_size as f64) * 100.0;

                    savings
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_tree_compaction,
    bench_tree_rebalancing,
    bench_redundant_data_removal,
    bench_full_optimization,
    bench_memory_usage_comparison,
    bench_workspace_optimization,
    bench_tree_migration_optimization,
    bench_optimization_effectiveness
);

criterion_main!(benches);

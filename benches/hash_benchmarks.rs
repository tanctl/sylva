use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use sylva::hash::{
    Blake3Hasher, EntryHashContext, Hash, HashOutput, HashRegistry, KeccakHasher, Sha256Hasher,
};
use uuid::Uuid;

fn bench_hash_bytes(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("hash_bytes");

    for size in [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        let data = vec![0xAB; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("blake3", size), size, |b, &_size| {
            b.iter(|| hasher.hash_bytes(black_box(&data)).unwrap());
        });
    }

    group.finish();
}

fn bench_hash_pair(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let left = hasher.hash_bytes(b"left_input_data").unwrap();
    let right = hasher.hash_bytes(b"right_input_data").unwrap();

    c.bench_function("hash_pair", |b| {
        b.iter(|| {
            hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap()
        });
    });
}

fn bench_hash_entry(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("hash_entry");

    for metadata_count in [0, 1, 5, 10, 50, 100].iter() {
        let mut metadata = HashMap::new();
        for i in 0..*metadata_count {
            metadata.insert(format!("key_{}", i), format!("value_with_some_data_{}", i));
        }

        let context = EntryHashContext {
            entry_id: Uuid::new_v4(),
            version: 1,
            timestamp: 1234567890,
            previous_id: None,
            content_type: Some("application/octet-stream".to_string()),
            metadata,
        };

        let data = vec![0x42; 1024]; // 1kb of data

        group.bench_with_input(
            BenchmarkId::new("metadata_items", metadata_count),
            metadata_count,
            |b, &_count| {
                b.iter(|| {
                    hasher
                        .hash_entry(black_box(&data), black_box(&context))
                        .unwrap()
                });
            },
        );
    }

    group.finish();
}

fn bench_hash_entry_data_sizes(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("hash_entry_data_sizes");

    let context = EntryHashContext {
        entry_id: Uuid::new_v4(),
        version: 1,
        timestamp: 1234567890,
        previous_id: None,
        content_type: Some("application/octet-stream".to_string()),
        metadata: HashMap::new(),
    };

    for size in [64, 256, 1024, 4096, 16384, 65536].iter() {
        let data = vec![0x42; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("data_size", size), size, |b, &_size| {
            b.iter(|| {
                hasher
                    .hash_entry(black_box(&data), black_box(&context))
                    .unwrap()
            });
        });
    }

    group.finish();
}

fn bench_hash_many(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("hash_many");

    for input_count in [1, 2, 5, 10, 20, 50, 100].iter() {
        let inputs: Vec<Vec<u8>> = (0..*input_count)
            .map(|i| format!("input_data_{}", i).into_bytes())
            .collect();
        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::new("input_count", input_count),
            input_count,
            |b, &_count| {
                b.iter(|| hasher.hash_many(black_box(&input_refs)).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_merkle_tree_construction(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("merkle_tree_construction");

    for leaf_count in [8, 16, 32, 64, 128, 256, 512, 1024].iter() {
        let leaves: Vec<HashOutput> = (0..*leaf_count)
            .map(|i| hasher.hash_bytes(format!("leaf_{}", i).as_bytes()).unwrap())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("leaves", leaf_count),
            leaf_count,
            |b, &_count| {
                b.iter(|| {
                    let mut current_level = black_box(&leaves).clone();
                    while current_level.len() > 1 {
                        let mut next_level = Vec::new();
                        for i in (0..current_level.len()).step_by(2) {
                            let left = &current_level[i];
                            let right = if i + 1 < current_level.len() {
                                &current_level[i + 1]
                            } else {
                                left
                            };
                            let parent = hasher.hash_pair(left, right).unwrap();
                            next_level.push(parent);
                        }
                        current_level = next_level;
                    }
                    current_level[0].clone()
                });
            },
        );
    }

    group.finish();
}

fn bench_ledger_chain_simulation(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("ledger_chain_simulation");

    for chain_length in [10, 50, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("chain_length", chain_length),
            chain_length,
            |b, &count| {
                b.iter(|| {
                    let mut previous_id = None;
                    let entry_base_id = Uuid::new_v4();

                    for i in 0..count {
                        let entry_id = Uuid::new_v4();
                        let context = EntryHashContext {
                            entry_id,
                            version: i as u64 + 1,
                            timestamp: 1234567890 + i as u64,
                            previous_id,
                            content_type: Some("application/json".to_string()),
                            metadata: HashMap::new(),
                        };

                        let data = format!("{{\"id\": {}, \"data\": \"entry_data_{}\"}}", i, i);
                        let _hash = hasher
                            .hash_entry(black_box(data.as_bytes()), black_box(&context))
                            .unwrap();

                        previous_id = Some(entry_id);
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_hash_output_operations(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let hash = hasher
        .hash_bytes(b"test data for hash output operations")
        .unwrap();

    let mut group = c.benchmark_group("hash_output_operations");

    group.bench_function("to_hex", |b| {
        b.iter(|| black_box(&hash).to_hex());
    });

    let hex_string = hash.to_hex();
    group.bench_function("from_hex", |b| {
        b.iter(|| HashOutput::from_hex(black_box(&hex_string)).unwrap());
    });

    let bytes = hash.as_bytes();
    group.bench_function("from_slice", |b| {
        b.iter(|| HashOutput::from_slice(black_box(bytes)).unwrap());
    });

    group.finish();
}

fn bench_concurrent_hashing(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let hasher = Arc::new(Blake3Hasher::new());

    c.bench_function("concurrent_hash_bytes", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let hasher_clone = hasher.clone();
                    let data = format!("concurrent_data_{}", i);
                    thread::spawn(move || hasher_clone.hash_bytes(data.as_bytes()).unwrap())
                })
                .collect();

            for handle in handles {
                black_box(handle.join().unwrap());
            }
        });
    });
}

fn bench_versioned_entry_scenarios(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();

    let mut group = c.benchmark_group("versioned_entry_scenarios");

    group.bench_function("document_versioning", |b| {
        b.iter(|| {
            let document_id = Uuid::new_v4();
            let mut previous_id = None;

            for version in 1..=10 {
                let entry_id = Uuid::new_v4();
                let mut metadata = HashMap::new();
                metadata.insert("author".to_string(), "user123".to_string());
                metadata.insert("document_type".to_string(), "markdown".to_string());
                metadata.insert("title".to_string(), format!("Document v{}", version));

                let context = EntryHashContext {
                    entry_id,
                    version,
                    timestamp: 1234567890 + version * 3600,
                    previous_id,
                    content_type: Some("text/markdown".to_string()),
                    metadata,
                };

                let content =
                    format!(
                    "# Document Version {}\n\nThis is version {} of the document.\n\nContent: {}",
                    version, version, "x".repeat(version as usize * 100)
                );

                let _hash = hasher
                    .hash_entry(black_box(content.as_bytes()), black_box(&context))
                    .unwrap();
                previous_id = Some(entry_id);
            }
        });
    });

    group.bench_function("code_commits", |b| {
        b.iter(|| {
            let mut previous_commit = None;
            for commit in 1..=20 {
                let commit_id = Uuid::new_v4();
                let mut metadata = HashMap::new();
                metadata.insert("author".to_string(), "developer@example.com".to_string());
                metadata.insert("branch".to_string(), "main".to_string());
                metadata.insert("message".to_string(), format!("Commit #{}: Fixed bug", commit));

                let context = EntryHashContext {
                    entry_id: commit_id,
                    version: commit,
                    timestamp: 1234567890 + commit * 1800, // 30 minutes apart
                    previous_id: previous_commit,
                    content_type: Some("application/git-diff".to_string()),
                    metadata,
                };

                let diff_content = format!(
                    "+++ b/src/main.rs\n@@ -10,3 +10,4 @@\n fn main() {{\n     println!(\"Hello, world!\");\n+    // Version {}\n }}",
                    commit
                );
                let _hash = hasher.hash_entry(black_box(diff_content.as_bytes()), black_box(&context)).unwrap();
                previous_commit = Some(commit_id);
            }
        });
    });

    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    let mut group = c.benchmark_group("algorithm_comparison");

    // test different input sizes across all algorithms
    for size in [64, 1024, 16384, 65536, 262144].iter() {
        let data = vec![0xAB; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("blake3", size), size, |b, &_size| {
            b.iter(|| blake3_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, &_size| {
            b.iter(|| sha256_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("keccak256", size), size, |b, &_size| {
            b.iter(|| keccak_hasher.hash_bytes(black_box(&data)).unwrap());
        });
    }

    group.finish();
}

fn bench_hash_pair_comparison(c: &mut Criterion) {
    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    let blake3_left = blake3_hasher.hash_bytes(b"left_data").unwrap();
    let blake3_right = blake3_hasher.hash_bytes(b"right_data").unwrap();
    let sha256_left = sha256_hasher.hash_bytes(b"left_data").unwrap();
    let sha256_right = sha256_hasher.hash_bytes(b"right_data").unwrap();
    let keccak_left = keccak_hasher.hash_bytes(b"left_data").unwrap();
    let keccak_right = keccak_hasher.hash_bytes(b"right_data").unwrap();

    let mut group = c.benchmark_group("hash_pair_comparison");

    group.bench_function("blake3", |b| {
        b.iter(|| {
            blake3_hasher
                .hash_pair(black_box(&blake3_left), black_box(&blake3_right))
                .unwrap()
        });
    });

    group.bench_function("sha256", |b| {
        b.iter(|| {
            sha256_hasher
                .hash_pair(black_box(&sha256_left), black_box(&sha256_right))
                .unwrap()
        });
    });

    group.bench_function("keccak256", |b| {
        b.iter(|| {
            keccak_hasher
                .hash_pair(black_box(&keccak_left), black_box(&keccak_right))
                .unwrap()
        });
    });

    group.finish();
}

fn bench_hash_entry_comparison(c: &mut Criterion) {
    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    let mut metadata = HashMap::new();
    metadata.insert("author".to_string(), "benchmark_user".to_string());
    metadata.insert("type".to_string(), "benchmark_entry".to_string());
    metadata.insert("category".to_string(), "performance_test".to_string());

    let context = EntryHashContext {
        entry_id: Uuid::new_v4(),
        version: 1,
        timestamp: 1234567890,
        previous_id: None,
        content_type: Some("application/octet-stream".to_string()),
        metadata,
    };

    let data = vec![0x42; 1024]; // 1kb of data

    let mut group = c.benchmark_group("hash_entry_comparison");

    group.bench_function("blake3", |b| {
        b.iter(|| {
            blake3_hasher
                .hash_entry(black_box(&data), black_box(&context))
                .unwrap()
        });
    });

    group.bench_function("sha256", |b| {
        b.iter(|| {
            sha256_hasher
                .hash_entry(black_box(&data), black_box(&context))
                .unwrap()
        });
    });

    group.bench_function("keccak256", |b| {
        b.iter(|| {
            keccak_hasher
                .hash_entry(black_box(&data), black_box(&context))
                .unwrap()
        });
    });

    group.finish();
}

fn bench_registry_overhead(c: &mut Criterion) {
    let registry = HashRegistry::default();
    let data = vec![0x42; 1024];

    let mut group = c.benchmark_group("registry_overhead");

    group.bench_function("direct_blake3", |b| {
        b.iter(|| {
            let hasher = Blake3Hasher::new();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.bench_function("direct_sha256", |b| {
        b.iter(|| {
            let hasher = Sha256Hasher::new();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.bench_function("direct_keccak256", |b| {
        b.iter(|| {
            let hasher = KeccakHasher::new();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.bench_function("registry_blake3", |b| {
        b.iter(|| {
            let hasher = registry.get_hasher("blake3").unwrap();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.bench_function("registry_sha256", |b| {
        b.iter(|| {
            let hasher = registry.get_hasher("sha256").unwrap();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.bench_function("registry_keccak256", |b| {
        b.iter(|| {
            let hasher = registry.get_hasher("keccak256").unwrap();
            hasher.hash_bytes(black_box(&data)).unwrap()
        });
    });

    group.finish();
}

fn bench_small_data_comparison(c: &mut Criterion) {
    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    let mut group = c.benchmark_group("small_data_comparison");

    for size in [8, 16, 32, 64].iter() {
        let data = vec![0xCD; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("blake3", size), size, |b, &_size| {
            b.iter(|| blake3_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, &_size| {
            b.iter(|| sha256_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("keccak256", size), size, |b, &_size| {
            b.iter(|| keccak_hasher.hash_bytes(black_box(&data)).unwrap());
        });
    }

    group.finish();
}

fn bench_large_data_comparison(c: &mut Criterion) {
    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    let mut group = c.benchmark_group("large_data_comparison");

    for size in [1048576, 4194304, 16777216].iter() {
        let data = vec![0xEF; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.sample_size(10); // reduce sample size for large data

        group.bench_with_input(BenchmarkId::new("blake3", size), size, |b, &_size| {
            b.iter(|| blake3_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, &_size| {
            b.iter(|| sha256_hasher.hash_bytes(black_box(&data)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("keccak256", size), size, |b, &_size| {
            b.iter(|| keccak_hasher.hash_bytes(black_box(&data)).unwrap());
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_bytes,
    bench_hash_pair,
    bench_hash_entry,
    bench_hash_entry_data_sizes,
    bench_hash_many,
    bench_merkle_tree_construction,
    bench_ledger_chain_simulation,
    bench_hash_output_operations,
    bench_concurrent_hashing,
    bench_versioned_entry_scenarios,
    bench_algorithm_comparison,
    bench_hash_pair_comparison,
    bench_hash_entry_comparison,
    bench_registry_overhead,
    bench_small_data_comparison,
    bench_large_data_comparison
);
criterion_main!(benches);

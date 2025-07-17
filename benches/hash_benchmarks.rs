use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sylva::hash::{
    Blake3Hasher, Hash, HashDigest, HashRegistry, KeccakHasher, LedgerEntryHashInput,
    PoseidonHasher, Sha256Hasher,
};
use uuid::Uuid;

fn benchmark_hash_bytes(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let mut group = c.benchmark_group("hash_bytes");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [1, 100, 1000, 10000].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = hasher.hash_bytes(black_box(&data)).unwrap();
            })
        });
    }
    group.finish();
}

fn benchmark_hash_pair(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let left = hasher.hash_bytes(b"left hash data").unwrap();
    let right = hasher.hash_bytes(b"right hash data").unwrap();

    c.bench_function("hash_pair", |b| {
        b.iter(|| {
            let _ = hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap();
        })
    });
}

fn benchmark_hash_entry(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let mut group = c.benchmark_group("hash_entry");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for data_size in [100, 1000].iter() {
        let entry = LedgerEntryHashInput {
            id: Uuid::new_v4(),
            data: vec![0u8; *data_size],
            timestamp: 1234567890,
            previous_hash: None,
        };

        group.throughput(Throughput::Bytes(*data_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(data_size), data_size, |b, _| {
            b.iter(|| {
                let _ = hasher.hash_entry(black_box(&entry)).unwrap();
            })
        });
    }
    group.finish();
}

fn benchmark_hash_entry_with_previous(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let previous_hash = hasher.hash_bytes(b"previous entry data").unwrap();

    let entry = LedgerEntryHashInput {
        id: Uuid::new_v4(),
        data: vec![0u8; 1000],
        timestamp: 1234567890,
        previous_hash: Some(previous_hash),
    };

    c.bench_function("hash_entry_with_previous", |b| {
        b.iter(|| {
            let _ = hasher.hash_entry(black_box(&entry)).unwrap();
        })
    });
}

fn benchmark_merkle_tree_simulation(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let mut group = c.benchmark_group("merkle_tree_simulation");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for leaf_count in [8, 16, 32, 64].iter() {
        // Create leaf hashes
        let leaves: Vec<HashDigest> = (0..*leaf_count)
            .map(|i| hasher.hash_bytes(format!("leaf_{}", i).as_bytes()).unwrap())
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    let mut level = black_box(leaves.clone());
                    while level.len() > 1 {
                        let mut next_level = Vec::new();
                        for chunk in level.chunks(2) {
                            if chunk.len() == 2 {
                                next_level.push(hasher.hash_pair(&chunk[0], &chunk[1]).unwrap());
                            } else {
                                next_level.push(chunk[0].clone());
                            }
                        }
                        level = next_level;
                    }
                })
            },
        );
    }
    group.finish();
}

fn benchmark_versioned_ledger_scenario(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let mut group = c.benchmark_group("versioned_ledger_scenario");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    // Simulate a versioned ledger with chain of entries
    for chain_length in [10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(chain_length),
            chain_length,
            |b, _| {
                b.iter(|| {
                    let mut previous_hash = None;
                    for i in 0..*chain_length {
                        let entry = LedgerEntryHashInput {
                            id: Uuid::new_v4(),
                            data: format!("entry_{}", i).into_bytes(),
                            timestamp: 1234567890 + i as u64,
                            previous_hash: previous_hash.clone(),
                        };

                        let hash = hasher.hash_entry(black_box(&entry)).unwrap();
                        previous_hash = Some(hash);
                    }
                })
            },
        );
    }
    group.finish();
}

fn benchmark_concurrent_hashing(c: &mut Criterion) {
    let hasher = Blake3Hasher::new();
    let data = vec![0u8; 1000];

    c.bench_function("concurrent_hashing", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let hasher = hasher.clone();
                    let data = data.clone();
                    std::thread::spawn(move || hasher.hash_bytes(&data).unwrap())
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

fn benchmark_hash_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_comparison");

    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();
    let poseidon_hasher = PoseidonHasher::new();

    let data = vec![0u8; 1000];

    group.bench_function("blake3_1kb", |b| {
        b.iter(|| {
            let _ = blake3_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("sha256_1kb", |b| {
        b.iter(|| {
            let _ = sha256_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("keccak_1kb", |b| {
        b.iter(|| {
            let _ = keccak_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("poseidon_1kb", |b| {
        b.iter(|| {
            let _ = poseidon_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.finish();
}

fn benchmark_hash_pair_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_pair_comparison");

    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();
    let poseidon_hasher = PoseidonHasher::new();

    let left = blake3_hasher.hash_bytes(b"left").unwrap();
    let right = blake3_hasher.hash_bytes(b"right").unwrap();

    group.bench_function("blake3_pair", |b| {
        b.iter(|| {
            let _ = blake3_hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap();
        })
    });

    group.bench_function("sha256_pair", |b| {
        b.iter(|| {
            let _ = sha256_hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap();
        })
    });

    group.bench_function("keccak_pair", |b| {
        b.iter(|| {
            let _ = keccak_hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap();
        })
    });

    group.bench_function("poseidon_pair", |b| {
        b.iter(|| {
            let _ = poseidon_hasher
                .hash_pair(black_box(&left), black_box(&right))
                .unwrap();
        })
    });

    group.finish();
}

fn benchmark_hash_entry_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_entry_comparison");

    let blake3_hasher = Blake3Hasher::new();
    let sha256_hasher = Sha256Hasher::new();
    let keccak_hasher = KeccakHasher::new();
    let poseidon_hasher = PoseidonHasher::new();

    let entry = LedgerEntryHashInput {
        id: Uuid::new_v4(),
        data: vec![0u8; 1000],
        timestamp: 1234567890,
        previous_hash: None,
    };

    group.bench_function("blake3_entry", |b| {
        b.iter(|| {
            let _ = blake3_hasher.hash_entry(black_box(&entry)).unwrap();
        })
    });

    group.bench_function("sha256_entry", |b| {
        b.iter(|| {
            let _ = sha256_hasher.hash_entry(black_box(&entry)).unwrap();
        })
    });

    group.bench_function("keccak_entry", |b| {
        b.iter(|| {
            let _ = keccak_hasher.hash_entry(black_box(&entry)).unwrap();
        })
    });

    group.bench_function("poseidon_entry", |b| {
        b.iter(|| {
            let _ = poseidon_hasher.hash_entry(black_box(&entry)).unwrap();
        })
    });

    group.finish();
}

fn benchmark_registry_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry_performance");

    let registry = HashRegistry::new();
    let data = vec![0u8; 1000];

    for hasher_name in &[
        "blake3",
        "sha256",
        "keccak",
        "poseidon",
        "poseidon-merkle",
        "poseidon-ethereum",
    ] {
        group.bench_function(&format!("registry_{}", hasher_name), |b| {
            b.iter(|| {
                let hasher = registry.get_hasher(black_box(hasher_name)).unwrap();
                let _ = hasher.hash_bytes(black_box(&data)).unwrap();
            })
        });
    }

    group.finish();
}

fn benchmark_poseidon_configurations(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon_configurations");

    let default_hasher = PoseidonHasher::new();
    let merkle_hasher = PoseidonHasher::for_merkle_tree().unwrap();
    let ethereum_hasher = PoseidonHasher::for_ethereum().unwrap();
    let batch_hasher = PoseidonHasher::for_batch_hash(5).unwrap();

    let data = vec![0u8; 1000];

    group.bench_function("poseidon_default", |b| {
        b.iter(|| {
            let _ = default_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("poseidon_merkle", |b| {
        b.iter(|| {
            let _ = merkle_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("poseidon_ethereum", |b| {
        b.iter(|| {
            let _ = ethereum_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.bench_function("poseidon_batch", |b| {
        b.iter(|| {
            let _ = batch_hasher.hash_bytes(black_box(&data)).unwrap();
        })
    });

    group.finish();
}

fn benchmark_poseidon_multiple_inputs(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon_multiple_inputs");

    for arity in [2, 3, 5, 8, 10, 12].iter() {
        let hasher = PoseidonHasher::for_batch_hash(*arity).unwrap();
        let inputs: Vec<_> = (0..*arity)
            .map(|i| format!("input_{}", i).into_bytes())
            .collect();
        let input_refs: Vec<_> = inputs.iter().map(|v| v.as_slice()).collect();

        group.bench_with_input(BenchmarkId::from_parameter(arity), arity, |b, _| {
            b.iter(|| {
                let _ = hasher.hash_multiple(black_box(&input_refs)).unwrap();
            })
        });
    }

    group.finish();
}

fn benchmark_zk_merkle_tree_poseidon(c: &mut Criterion) {
    let hasher = PoseidonHasher::for_merkle_tree().unwrap();
    let mut group = c.benchmark_group("zk_merkle_tree_poseidon");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for leaf_count in [8, 16, 32, 64, 128].iter() {
        // Create leaf hashes
        let leaves: Vec<HashDigest> = (0..*leaf_count)
            .map(|i| {
                hasher
                    .hash_bytes(format!("zk_leaf_{}", i).as_bytes())
                    .unwrap()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    let mut level = black_box(leaves.clone());
                    while level.len() > 1 {
                        let mut next_level = Vec::new();
                        for chunk in level.chunks(2) {
                            if chunk.len() == 2 {
                                next_level.push(hasher.hash_pair(&chunk[0], &chunk[1]).unwrap());
                            } else {
                                next_level.push(chunk[0].clone());
                            }
                        }
                        level = next_level;
                    }
                })
            },
        );
    }

    group.finish();
}

fn benchmark_poseidon_vs_others_zk_scenario(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon_vs_others_zk_scenario");

    let poseidon_hasher = PoseidonHasher::new();
    let blake3_hasher = Blake3Hasher::new();
    let keccak_hasher = KeccakHasher::new();

    // Simulate a ZK-friendly scenario with multiple hash operations
    let inputs = [b"zk_input1", b"zk_input2", b"zk_input3", b"zk_input4"];

    group.bench_function("poseidon_zk_scenario", |b| {
        b.iter(|| {
            let mut hashes = Vec::new();
            for input in &inputs {
                hashes.push(poseidon_hasher.hash_bytes(black_box(*input)).unwrap());
            }

            // Build a mini Merkle tree
            let left_pair = poseidon_hasher.hash_pair(&hashes[0], &hashes[1]).unwrap();
            let right_pair = poseidon_hasher.hash_pair(&hashes[2], &hashes[3]).unwrap();
            let _ = poseidon_hasher.hash_pair(&left_pair, &right_pair).unwrap();
        })
    });

    group.bench_function("blake3_zk_scenario", |b| {
        b.iter(|| {
            let mut hashes = Vec::new();
            for input in &inputs {
                hashes.push(blake3_hasher.hash_bytes(black_box(*input)).unwrap());
            }

            // Build a mini Merkle tree
            let left_pair = blake3_hasher.hash_pair(&hashes[0], &hashes[1]).unwrap();
            let right_pair = blake3_hasher.hash_pair(&hashes[2], &hashes[3]).unwrap();
            let _ = blake3_hasher.hash_pair(&left_pair, &right_pair).unwrap();
        })
    });

    group.bench_function("keccak_zk_scenario", |b| {
        b.iter(|| {
            let mut hashes = Vec::new();
            for input in &inputs {
                hashes.push(keccak_hasher.hash_bytes(black_box(*input)).unwrap());
            }

            // Build a mini Merkle tree
            let left_pair = keccak_hasher.hash_pair(&hashes[0], &hashes[1]).unwrap();
            let right_pair = keccak_hasher.hash_pair(&hashes[2], &hashes[3]).unwrap();
            let _ = keccak_hasher.hash_pair(&left_pair, &right_pair).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_hash_bytes,
    benchmark_hash_pair,
    benchmark_hash_entry,
    benchmark_hash_entry_with_previous,
    benchmark_merkle_tree_simulation,
    benchmark_versioned_ledger_scenario,
    benchmark_concurrent_hashing,
    benchmark_hash_comparison,
    benchmark_hash_pair_comparison,
    benchmark_hash_entry_comparison,
    benchmark_registry_performance,
    benchmark_poseidon_configurations,
    benchmark_poseidon_multiple_inputs,
    benchmark_zk_merkle_tree_poseidon,
    benchmark_poseidon_vs_others_zk_scenario
);
criterion_main!(benches);

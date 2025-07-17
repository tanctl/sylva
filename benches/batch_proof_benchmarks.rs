use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sylva::hash::{Blake3Hasher, Hash as HashTrait, HashDigest};
use sylva::proof::batch::{BatchConfig, BatchProofGenerator, BatchProofVerifier};
use sylva::proof::inclusion::InclusionProof;
use uuid::Uuid;

fn create_test_leaf_hash(data: &[u8]) -> HashDigest {
    let hasher = Blake3Hasher::new();
    hasher.hash_bytes(data).unwrap()
}

fn setup_test_data(size: usize) -> (Vec<HashDigest>, Vec<usize>, Vec<Uuid>) {
    let leaves: Vec<HashDigest> = (0..size)
        .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
        .collect();

    let indices: Vec<usize> = (0..size.min(100)).collect(); // Test with up to 100 proofs
    let entry_ids: Vec<Uuid> = (0..indices.len()).map(|_| Uuid::new_v4()).collect();

    (leaves, indices, entry_ids)
}

fn bench_individual_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("individual_proof_generation");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [100, 500, 1000].iter() {
        let (leaves, indices, entry_ids) = setup_test_data(*size);

        group.throughput(Throughput::Elements(indices.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("individual", size),
            &(leaves, indices, entry_ids),
            |b, (leaves, indices, entry_ids)| {
                b.iter(|| {
                    let mut proofs = Vec::new();
                    for (&idx, &entry_id) in indices.iter().zip(entry_ids.iter()) {
                        let proof = InclusionProof::generate_for_leaf_index(
                            black_box(entry_id),
                            black_box(idx),
                            black_box(leaves),
                        )
                        .unwrap();
                        proofs.push(proof);
                    }
                    black_box(proofs)
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_proof_generation");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [100, 500, 1000].iter() {
        let (leaves, indices, entry_ids) = setup_test_data(*size);

        group.throughput(Throughput::Elements(indices.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_sequential", size),
            &(leaves.clone(), indices.clone(), entry_ids.clone()),
            |b, (leaves, indices, entry_ids)| {
                let generator = BatchProofGenerator::new(leaves).unwrap();
                let config = BatchConfig {
                    parallel: false,
                    show_progress: false,
                    chunk_size: 1000,
                    memory_limit: 0,
                };

                b.iter(|| {
                    let result = generator
                        .generate_batch_proofs(
                            black_box(indices),
                            black_box(entry_ids),
                            black_box(&config),
                        )
                        .unwrap();
                    black_box(result)
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("batch_parallel", size),
            &(leaves, indices, entry_ids),
            |b, (leaves, indices, entry_ids)| {
                let generator = BatchProofGenerator::new(leaves).unwrap();
                let config = BatchConfig {
                    parallel: true,
                    show_progress: false,
                    chunk_size: 25,
                    memory_limit: 0,
                };

                b.iter(|| {
                    let result = generator
                        .generate_batch_proofs(
                            black_box(indices),
                            black_box(entry_ids),
                            black_box(&config),
                        )
                        .unwrap();
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_individual_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("individual_proof_verification");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [100, 500].iter() {
        let (leaves, indices, entry_ids) = setup_test_data(*size);
        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let config = BatchConfig::default();
        let batch_result = generator
            .generate_batch_proofs(&indices, &entry_ids, &config)
            .unwrap();
        let root_hash = generator.root_hash().clone();

        group.throughput(Throughput::Elements(batch_result.proofs.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("individual", size),
            &(*size, batch_result.proofs, root_hash),
            |b, (_size, proofs, root_hash): &(usize, Vec<InclusionProof>, HashDigest)| {
                b.iter(|| {
                    let mut results = Vec::new();
                    for proof in proofs {
                        let result = proof.verify_against_root(black_box(root_hash));
                        results.push(result.is_ok());
                    }
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

fn bench_batch_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_proof_verification");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [100, 500].iter() {
        let (leaves, indices, entry_ids) = setup_test_data(*size);
        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let config = BatchConfig::default();
        let batch_result = generator
            .generate_batch_proofs(&indices, &entry_ids, &config)
            .unwrap();
        let root_hash = generator.root_hash().clone();

        group.throughput(Throughput::Elements(batch_result.proofs.len() as u64));

        // Sequential verification benchmark
        let proofs_clone = batch_result.proofs.clone();
        let root_hash_clone = root_hash.clone();
        group.bench_with_input(
            BenchmarkId::new("batch_sequential", size),
            &(*size, proofs_clone, root_hash_clone),
            |b, (_size, proofs, root_hash): &(usize, Vec<InclusionProof>, HashDigest)| {
                let mut verifier = BatchProofVerifier::new(root_hash.clone());
                let config = BatchConfig {
                    parallel: false,
                    show_progress: false,
                    chunk_size: 1000,
                    memory_limit: 0,
                };

                b.iter(|| {
                    let result = verifier.verify_batch(black_box(proofs), black_box(&config));
                    black_box(result)
                });
            },
        );

        // Parallel verification benchmark
        group.bench_with_input(
            BenchmarkId::new("batch_parallel", size),
            &(*size, batch_result.proofs, root_hash),
            |b, (_size, proofs, root_hash): &(usize, Vec<InclusionProof>, HashDigest)| {
                let mut verifier = BatchProofVerifier::new(root_hash.clone());
                let config = BatchConfig {
                    parallel: true,
                    show_progress: false,
                    chunk_size: 25,
                    memory_limit: 0,
                };

                b.iter(|| {
                    let result = verifier.verify_batch(black_box(proofs), black_box(&config));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for size in [100, 500, 1000].iter() {
        let leaves: Vec<HashDigest> = (0..*size)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("tree_cache_creation", size),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let generator = BatchProofGenerator::new(black_box(leaves)).unwrap();
                    black_box(generator)
                });
            },
        );
    }

    group.finish();
}

fn bench_scalability_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability_comparison");
    group.sample_size(20); // Reduce sample size for large benchmarks

    for proof_count in [10, 50, 100, 200].iter() {
        let tree_size = 1000;
        let (leaves, indices, entry_ids) = {
            let leaves: Vec<HashDigest> = (0..tree_size)
                .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
                .collect();
            let indices: Vec<usize> = (0..*proof_count).collect();
            let entry_ids: Vec<Uuid> = (0..*proof_count).map(|_| Uuid::new_v4()).collect();
            (leaves, indices, entry_ids)
        };

        // Individual approach
        group.throughput(Throughput::Elements(*proof_count as u64));
        group.bench_with_input(
            BenchmarkId::new("individual", proof_count),
            &(leaves.clone(), indices.clone(), entry_ids.clone()),
            |b, (leaves, indices, entry_ids)| {
                b.iter(|| {
                    let mut proofs = Vec::new();
                    for (&idx, &entry_id) in indices.iter().zip(entry_ids.iter()) {
                        let proof = InclusionProof::generate_for_leaf_index(
                            black_box(entry_id),
                            black_box(idx),
                            black_box(leaves),
                        )
                        .unwrap();
                        proofs.push(proof);
                    }
                    black_box(proofs)
                });
            },
        );

        // Batch approach
        group.bench_with_input(
            BenchmarkId::new("batch", proof_count),
            &(leaves, indices, entry_ids),
            |b, (leaves, indices, entry_ids)| {
                let generator = BatchProofGenerator::new(leaves).unwrap();
                let config = BatchConfig {
                    parallel: true,
                    show_progress: false,
                    chunk_size: 50,
                    memory_limit: 0,
                };

                b.iter(|| {
                    let result = generator
                        .generate_batch_proofs(
                            black_box(indices),
                            black_box(entry_ids),
                            black_box(&config),
                        )
                        .unwrap();
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

fn bench_tree_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_size_impact");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    let proof_count = 50;
    for tree_size in [100, 500, 1000].iter() {
        let (leaves, indices, entry_ids) = {
            let leaves: Vec<HashDigest> = (0..*tree_size)
                .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
                .collect();
            let indices: Vec<usize> = (0..proof_count).collect();
            let entry_ids: Vec<Uuid> = (0..proof_count).map(|_| Uuid::new_v4()).collect();
            (leaves, indices, entry_ids)
        };

        group.throughput(Throughput::Elements(proof_count as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_generation", tree_size),
            &(leaves, indices, entry_ids),
            |b, (leaves, indices, entry_ids)| {
                let generator = BatchProofGenerator::new(leaves).unwrap();
                let config = BatchConfig::default();

                b.iter(|| {
                    let result = generator
                        .generate_batch_proofs(
                            black_box(indices),
                            black_box(entry_ids),
                            black_box(&config),
                        )
                        .unwrap();
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_individual_proof_generation,
    bench_batch_proof_generation,
    bench_individual_proof_verification,
    bench_batch_proof_verification,
    bench_memory_usage,
    bench_scalability_comparison,
    bench_tree_sizes
);

criterion_main!(benches);

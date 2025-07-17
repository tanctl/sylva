use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use sylva::ledger::Ledger;
use sylva::storage::compression::{
    CompressionAlgorithm, CompressionAnalyzer, CompressionConfig, Compressor,
};
use sylva::storage::{LedgerStorage, StorageFormat};
use sylva::workspace::Workspace;
use tempfile::TempDir;

fn create_test_data(size: usize, repetitiveness: f64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let base_pattern = b"This is a test pattern for compression benchmarking. ";
    let random_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    let pattern_size = (size as f64 * repetitiveness) as usize;
    let random_size = size - pattern_size;

    // Add repetitive data
    for _ in 0..(pattern_size / base_pattern.len() + 1) {
        for &byte in base_pattern {
            if data.len() < pattern_size {
                data.push(byte);
            }
        }
    }

    // Add random data
    for i in 0..random_size {
        data.push(random_chars[i % random_chars.len()]);
    }

    data.truncate(size);
    data
}

fn create_test_ledger(entry_count: usize, entry_size: usize) -> Ledger {
    let mut ledger = Ledger::new();

    for i in 0..entry_count {
        let data = create_test_data(entry_size, 0.7); // 70% repetitive
        let mut metadata = HashMap::new();
        metadata.insert("index".to_string(), i.to_string());
        metadata.insert("type".to_string(), "benchmark_entry".to_string());

        ledger.add_entry_with_metadata(data, metadata).unwrap();
    }

    ledger
}

fn bench_compression_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_algorithms");
    group.sample_size(20);

    let data_sizes = [1024, 8192, 65536, 262144]; // 1KB, 8KB, 64KB, 256KB
    let algorithms = [CompressionAlgorithm::None, CompressionAlgorithm::Zstd];

    for &size in &data_sizes {
        let data = create_test_data(size, 0.6);
        group.throughput(Throughput::Bytes(size as u64));

        for &algorithm in &algorithms {
            let config = if algorithm == CompressionAlgorithm::None {
                CompressionConfig::new(algorithm, 0).unwrap()
            } else {
                CompressionConfig::new(algorithm, 3).unwrap()
            };

            let compressor = Compressor::new(config).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("{:?}", algorithm), size),
                &data,
                |b, data| {
                    b.iter(|| {
                        let compressed = compressor.compress(black_box(data)).unwrap();
                        let _decompressed = compressor.decompress(black_box(&compressed)).unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_compression_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_levels");
    group.sample_size(15);

    let data = create_test_data(32768, 0.8); // 32KB with high repetitiveness
    group.throughput(Throughput::Bytes(data.len() as u64));

    for level in [1, 3, 6, 9, 12, 15, 19, 22] {
        let config = CompressionConfig::new(CompressionAlgorithm::Zstd, level).unwrap();
        let compressor = Compressor::new(config).unwrap();

        group.bench_with_input(BenchmarkId::new("zstd_level", level), &data, |b, data| {
            b.iter(|| {
                let compressed = compressor.compress(black_box(data)).unwrap();
                black_box(compressed)
            });
        });
    }

    group.finish();
}

fn bench_ledger_storage_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("ledger_storage_formats");
    group.sample_size(10);

    let temp_dir = TempDir::new().unwrap();
    let workspace = Workspace::init(temp_dir.path()).unwrap();
    let storage = LedgerStorage::new(&workspace).unwrap();

    let entry_counts = [10, 50, 100, 200];
    let formats = [
        StorageFormat::Json,
        StorageFormat::Binary,
        StorageFormat::CompressedJson,
        StorageFormat::CompressedBinary,
    ];

    for &entry_count in &entry_counts {
        let ledger = create_test_ledger(entry_count, 1024); // 1KB entries

        for &format in &formats {
            group.bench_with_input(
                BenchmarkId::new(format!("{:?}", format), entry_count),
                &(&ledger, format),
                |b, (ledger, format)| {
                    b.iter(|| {
                        let ledger_id = storage
                            .save_ledger_with_format(
                                black_box(ledger),
                                "benchmark_ledger",
                                black_box(*format),
                            )
                            .unwrap();

                        let _loaded = storage.load_ledger(black_box(&ledger_id)).unwrap();

                        // Clean up
                        storage.delete_ledger(&ledger_id).unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_compression_ratio_vs_speed(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratio_vs_speed");
    group.sample_size(10);

    let data_types = [
        ("highly_repetitive", create_test_data(65536, 0.9)),
        ("moderately_repetitive", create_test_data(65536, 0.5)),
        ("random_data", create_test_data(65536, 0.1)),
    ];

    for (data_type, data) in &data_types {
        group.throughput(Throughput::Bytes(data.len() as u64));

        // Test different compression levels
        for level in [1, 6, 12, 22] {
            let config = CompressionConfig::new(CompressionAlgorithm::Zstd, level).unwrap();
            let compressor = Compressor::new(config).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("{}_{}", data_type, level), data.len()),
                data,
                |b, data| {
                    b.iter(|| {
                        let compressed = compressor.compress(black_box(data)).unwrap();
                        black_box(compressed)
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_compression_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_memory_usage");
    group.sample_size(10);

    let sizes = [4096, 16384, 65536, 262144, 1048576]; // 4KB to 1MB

    for &size in &sizes {
        let data = create_test_data(size, 0.7);
        group.throughput(Throughput::Bytes(size as u64));

        // Test memory-efficient compression
        let config = CompressionConfig::new(CompressionAlgorithm::Zstd, 3).unwrap();
        let compressor = Compressor::new(config).unwrap();

        group.bench_with_input(BenchmarkId::new("memory_usage", size), &data, |b, data| {
            b.iter(|| {
                let compressed = compressor.compress(black_box(data)).unwrap();
                let estimated_memory = CompressionAnalyzer::estimate_memory_usage(
                    data.len(),
                    CompressionAlgorithm::Zstd,
                );
                black_box((compressed, estimated_memory))
            });
        });
    }

    group.finish();
}

fn bench_decompression_speed(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression_speed");
    group.sample_size(20);

    let sizes = [8192, 32768, 131072]; // 8KB, 32KB, 128KB

    for &size in &sizes {
        let data = create_test_data(size, 0.8);
        group.throughput(Throughput::Bytes(size as u64));

        // Pre-compress the data at different levels
        for level in [1, 6, 15] {
            let config = CompressionConfig::new(CompressionAlgorithm::Zstd, level).unwrap();
            let compressor = Compressor::new(config).unwrap();
            let compressed = compressor.compress(&data).unwrap();

            group.bench_with_input(
                BenchmarkId::new(format!("decompress_level_{}", level), size),
                &compressed,
                |b, compressed| {
                    b.iter(|| {
                        let _decompressed = compressor.decompress(black_box(compressed)).unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_compression_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_analysis");
    group.sample_size(5); // Fewer samples since this is expensive

    let test_data = create_test_data(65536, 0.6);

    group.bench_function("find_optimal_level", |b| {
        b.iter(|| {
            let (_level, _stats) = CompressionAnalyzer::find_optimal_level(
                black_box(&test_data),
                CompressionAlgorithm::Zstd,
            )
            .unwrap();
        });
    });

    group.bench_function("compare_algorithms", |b| {
        b.iter(|| {
            let _results = CompressionAnalyzer::compare_algorithms(black_box(&test_data)).unwrap();
        });
    });

    group.finish();
}

fn bench_large_ledger_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_ledger_compression");
    group.sample_size(5);

    let temp_dir = TempDir::new().unwrap();
    let workspace = Workspace::init(temp_dir.path()).unwrap();
    let storage = LedgerStorage::new(&workspace).unwrap();

    // Create large ledgers with varying characteristics
    let ledger_configs = [
        ("small_entries_many", 1000, 512), // 1000 entries, 512 bytes each
        ("large_entries_few", 50, 10240),  // 50 entries, 10KB each
        ("medium_mixed", 200, 2048),       // 200 entries, 2KB each
    ];

    for (name, entry_count, entry_size) in &ledger_configs {
        let ledger = create_test_ledger(*entry_count, *entry_size);
        let total_size = entry_count * entry_size;
        group.throughput(Throughput::Bytes(total_size as u64));

        // Test compressed vs uncompressed storage
        for format in [StorageFormat::Json, StorageFormat::CompressedJson] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_{:?}", name, format), total_size),
                &(&ledger, format),
                |b, (ledger, format)| {
                    b.iter(|| {
                        let ledger_id = storage
                            .save_ledger_with_format(
                                black_box(ledger),
                                "large_benchmark",
                                black_box(*format),
                            )
                            .unwrap();

                        let _loaded = storage.load_ledger(black_box(&ledger_id)).unwrap();

                        // Clean up
                        storage.delete_ledger(&ledger_id).unwrap();
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    compression_benches,
    bench_compression_algorithms,
    bench_compression_levels,
    bench_ledger_storage_formats,
    bench_compression_ratio_vs_speed,
    bench_compression_memory_usage,
    bench_decompression_speed,
    bench_compression_analysis,
    bench_large_ledger_compression
);

criterion_main!(compression_benches);

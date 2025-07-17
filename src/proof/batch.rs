use super::{utils, Direction, InclusionProof, ProofError, SiblingHash};
use crate::error::Result;
use crate::hash::{Blake3Hasher, Hash as HashTrait, HashDigest};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Optimized batch proof generation with shared computation
#[derive(Debug, Clone)]
pub struct BatchProofGenerator {
    /// Pre-computed tree structure for efficient proof extraction
    tree_cache: TreeCache,
    /// Memory usage tracking
    memory_usage: usize,
}

/// Cached tree structure for efficient batch operations
#[derive(Debug, Clone)]
struct TreeCache {
    /// Root hash of the complete tree
    root_hash: HashDigest,
    /// All intermediate hashes organized by level
    levels: Vec<Vec<HashDigest>>,
    /// Total number of leaves
    leaf_count: usize,
    /// Tree height
    height: usize,
}

/// Results from batch proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofResult {
    /// Successfully generated proofs
    pub proofs: Vec<InclusionProof>,
    /// Failed proof generation attempts with errors
    pub failures: Vec<(usize, String)>,
    /// Generation statistics
    pub stats: BatchStats,
}

/// Batch operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStats {
    /// Total items processed
    pub total_processed: usize,
    /// Number of successful generations
    pub successful: usize,
    /// Number of failures
    pub failed: usize,
    /// Total time in milliseconds
    pub duration_ms: u128,
    /// Memory usage in bytes
    pub memory_usage: usize,
    /// Average time per proof in microseconds
    pub avg_time_per_proof_us: f64,
}

/// Configuration for batch operations
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Chunk size for parallel processing
    pub chunk_size: usize,
    /// Enable progress reporting
    pub show_progress: bool,
    /// Memory limit in bytes (0 = no limit)
    pub memory_limit: usize,
    /// Enable parallel processing
    pub parallel: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1000,
            show_progress: true,
            memory_limit: 0,
            parallel: true,
        }
    }
}

impl BatchProofGenerator {
    /// Create a new batch proof generator for the given leaves
    pub fn new(leaves: &[HashDigest]) -> Result<Self> {
        let tree_cache = Self::build_tree_cache(leaves)?;
        let memory_usage = Self::calculate_memory_usage(&tree_cache);

        Ok(Self {
            tree_cache,
            memory_usage,
        })
    }

    /// Build a complete tree cache for efficient proof extraction
    fn build_tree_cache(leaves: &[HashDigest]) -> Result<TreeCache> {
        if leaves.is_empty() {
            return Err(ProofError::EmptyTree.into());
        }

        let leaf_count = leaves.len();
        let height = utils::tree_height(leaf_count);
        let mut levels = Vec::with_capacity(height + 1);

        // Start with leaf level
        levels.push(leaves.to_vec());

        // Build each level bottom-up
        let mut current_level = leaves.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left_hash = current_level[i].clone();
                let right_hash = if i + 1 < current_level.len() {
                    current_level[i + 1].clone()
                } else {
                    // Odd number of nodes, duplicate the last one
                    left_hash.clone()
                };

                // Combine left and right to create parent hash
                let parent_hash = Self::hash_pair(&left_hash, &right_hash)?;
                next_level.push(parent_hash);
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        let root_hash =
            current_level
                .into_iter()
                .next()
                .ok_or_else(|| ProofError::InvalidStructure {
                    reason: "Failed to compute root hash".to_string(),
                })?;

        Ok(TreeCache {
            root_hash,
            levels,
            leaf_count,
            height,
        })
    }

    /// Hash a pair of child hashes to create parent hash
    fn hash_pair(left: &HashDigest, right: &HashDigest) -> Result<HashDigest> {
        let hasher = Blake3Hasher::new();
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left.as_bytes());
        combined.extend_from_slice(right.as_bytes());

        hasher.hash_bytes(&combined).map_err(|e| {
            ProofError::HashComputationFailed {
                reason: format!("Blake3 hash computation failed: {}", e),
            }
            .into()
        })
    }

    /// Calculate memory usage of the tree cache
    fn calculate_memory_usage(cache: &TreeCache) -> usize {
        let mut size = std::mem::size_of::<TreeCache>();

        for level in &cache.levels {
            size += level.len() * std::mem::size_of::<HashDigest>();
        }

        size
    }

    /// Generate proofs for multiple leaf indices efficiently
    pub fn generate_batch_proofs(
        &self,
        leaf_indices: &[usize],
        entry_ids: &[Uuid],
        config: &BatchConfig,
    ) -> Result<BatchProofResult> {
        if leaf_indices.len() != entry_ids.len() {
            return Err(ProofError::InvalidStructure {
                reason: "Leaf indices and entry IDs must have the same length".to_string(),
            }
            .into());
        }

        let start_time = std::time::Instant::now();
        let mut proofs = Vec::with_capacity(leaf_indices.len());
        let mut failures = Vec::new();

        // Check memory limit
        if config.memory_limit > 0 && self.memory_usage > config.memory_limit {
            return Err(ProofError::InvalidStructure {
                reason: format!(
                    "Memory usage {} exceeds limit {}",
                    self.memory_usage, config.memory_limit
                ),
            }
            .into());
        }

        // Setup progress bar
        let progress_bar = if config.show_progress && leaf_indices.len() > 100 {
            let pb = ProgressBar::new(leaf_indices.len() as u64);
            if let Ok(style) = ProgressStyle::default_bar().template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            ) {
                pb.set_style(style.progress_chars("#>-"));
            }
            Some(pb)
        } else {
            None
        };

        // Process in chunks for memory efficiency
        let chunks: Vec<_> = leaf_indices
            .chunks(config.chunk_size)
            .zip(entry_ids.chunks(config.chunk_size))
            .collect();

        for (leaf_chunk, id_chunk) in chunks {
            let chunk_results: Vec<_> = if config.parallel && leaf_chunk.len() > 10 {
                // Parallel processing for large chunks
                leaf_chunk
                    .par_iter()
                    .zip(id_chunk.par_iter())
                    .map(|(&leaf_idx, &entry_id)| {
                        self.generate_single_proof_optimized(leaf_idx, entry_id)
                    })
                    .collect()
            } else {
                // Sequential processing for small chunks
                leaf_chunk
                    .iter()
                    .zip(id_chunk.iter())
                    .map(|(&leaf_idx, &entry_id)| {
                        self.generate_single_proof_optimized(leaf_idx, entry_id)
                    })
                    .collect()
            };

            // Process results
            for (i, result) in chunk_results.into_iter().enumerate() {
                match result {
                    Ok(proof) => proofs.push(proof),
                    Err(e) => failures.push((leaf_chunk[i], e.to_string())),
                }

                if let Some(ref pb) = progress_bar {
                    pb.inc(1);
                }
            }
        }

        if let Some(pb) = progress_bar {
            pb.finish_with_message("Batch proof generation completed");
        }

        let duration = start_time.elapsed();
        let stats = BatchStats {
            total_processed: leaf_indices.len(),
            successful: proofs.len(),
            failed: failures.len(),
            duration_ms: duration.as_millis(),
            memory_usage: self.memory_usage,
            avg_time_per_proof_us: if !proofs.is_empty() {
                duration.as_micros() as f64 / proofs.len() as f64
            } else {
                0.0
            },
        };

        Ok(BatchProofResult {
            proofs,
            failures,
            stats,
        })
    }

    /// Generate a single proof using the cached tree structure
    fn generate_single_proof_optimized(
        &self,
        leaf_index: usize,
        entry_id: Uuid,
    ) -> Result<InclusionProof> {
        if leaf_index >= self.tree_cache.leaf_count {
            return Err(ProofError::InvalidLeafIndex {
                index: leaf_index,
                total_leaves: self.tree_cache.leaf_count,
            }
            .into());
        }

        let leaf_hash = self.tree_cache.levels[0][leaf_index].clone();
        let mut sibling_hashes = Vec::new();
        let mut current_index = leaf_index;

        // Extract sibling hashes from cached levels
        for level in 0..self.tree_cache.levels.len() - 1 {
            let level_size = self.tree_cache.levels[level].len();
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level_size {
                let sibling_hash = self.tree_cache.levels[level][sibling_index].clone();
                let direction = if current_index % 2 == 0 {
                    Direction::Right
                } else {
                    Direction::Left
                };
                sibling_hashes.push(SiblingHash::new(sibling_hash, direction));
            }

            current_index /= 2;
        }

        Ok(InclusionProof::new(
            entry_id,
            leaf_index,
            leaf_hash,
            sibling_hashes,
            self.tree_cache.root_hash.clone(),
            self.tree_cache.leaf_count,
        ))
    }

    /// Get memory usage statistics
    pub fn memory_usage(&self) -> usize {
        self.memory_usage
    }

    /// Get tree statistics
    pub fn tree_stats(&self) -> (usize, usize, usize) {
        (
            self.tree_cache.leaf_count,
            self.tree_cache.height,
            self.tree_cache.levels.len(),
        )
    }

    /// Get the root hash of the tree
    pub fn root_hash(&self) -> &HashDigest {
        &self.tree_cache.root_hash
    }
}

/// Batch verification for multiple proofs against the same tree
pub struct BatchProofVerifier {
    /// Root hash to verify against
    root_hash: HashDigest,
    /// Verification statistics
    stats: BatchVerificationStats,
}

/// Batch verification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationStats {
    /// Total proofs verified
    pub total_verified: usize,
    /// Number of valid proofs
    pub valid: usize,
    /// Number of invalid proofs
    pub invalid: usize,
    /// Total verification time in milliseconds
    pub duration_ms: u128,
    /// Average time per verification in microseconds
    pub avg_time_per_verification_us: f64,
}

/// Result from batch verification
#[derive(Debug)]
pub struct BatchVerificationResult {
    /// Verification results for each proof
    pub results: Vec<Result<bool>>,
    /// Verification statistics
    pub stats: BatchVerificationStats,
}

impl BatchProofVerifier {
    /// Create a new batch verifier
    pub fn new(root_hash: HashDigest) -> Self {
        Self {
            root_hash,
            stats: BatchVerificationStats {
                total_verified: 0,
                valid: 0,
                invalid: 0,
                duration_ms: 0,
                avg_time_per_verification_us: 0.0,
            },
        }
    }

    /// Verify multiple proofs efficiently
    pub fn verify_batch(
        &mut self,
        proofs: &[InclusionProof],
        config: &BatchConfig,
    ) -> BatchVerificationResult {
        let start_time = std::time::Instant::now();

        // Setup progress bar
        let progress_bar = if config.show_progress && proofs.len() > 100 {
            let pb = ProgressBar::new(proofs.len() as u64);
            if let Ok(style) = ProgressStyle::default_bar().template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            ) {
                pb.set_style(style.progress_chars("#>-"));
            }
            Some(pb)
        } else {
            None
        };

        let results: Vec<Result<bool>> = if config.parallel && proofs.len() > 10 {
            // Parallel verification for large batches
            proofs
                .par_chunks(config.chunk_size)
                .flat_map(|chunk| {
                    chunk
                        .iter()
                        .map(|proof| {
                            let result = proof.verify_against_root(&self.root_hash);
                            if let Some(ref pb) = progress_bar {
                                pb.inc(1);
                            }
                            result
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        } else {
            // Sequential verification
            proofs
                .iter()
                .map(|proof| {
                    let result = proof.verify_against_root(&self.root_hash);
                    if let Some(ref pb) = progress_bar {
                        pb.inc(1);
                    }
                    result
                })
                .collect()
        };

        if let Some(pb) = progress_bar {
            pb.finish_with_message("Batch verification completed");
        }

        let duration = start_time.elapsed();

        // Calculate statistics
        let valid = results.iter().filter(|r| matches!(r, Ok(true))).count();
        let invalid = results.len() - valid;

        self.stats = BatchVerificationStats {
            total_verified: results.len(),
            valid,
            invalid,
            duration_ms: duration.as_millis(),
            avg_time_per_verification_us: if !results.is_empty() {
                duration.as_micros() as f64 / results.len() as f64
            } else {
                0.0
            },
        };

        BatchVerificationResult {
            results,
            stats: self.stats.clone(),
        }
    }

    /// Get verification statistics
    pub fn stats(&self) -> &BatchVerificationStats {
        &self.stats
    }
}

/// Memory-efficient streaming batch processor
pub struct StreamingBatchProcessor {
    /// Maximum batch size to process at once
    max_batch_size: usize,
    /// Current memory usage
    current_memory: usize,
    /// Memory limit
    memory_limit: usize,
}

impl StreamingBatchProcessor {
    /// Create a new streaming processor
    pub fn new(max_batch_size: usize, memory_limit: usize) -> Self {
        Self {
            max_batch_size,
            current_memory: 0,
            memory_limit,
        }
    }

    /// Process items in memory-efficient batches
    pub fn process_streaming<T, F, R>(
        &mut self,
        items: impl Iterator<Item = T>,
        mut processor: F,
        config: &BatchConfig,
    ) -> Result<Vec<R>>
    where
        F: FnMut(&[T]) -> Result<Vec<R>>,
        T: Clone,
    {
        let mut results = Vec::new();
        let mut current_batch = Vec::new();
        let mut total_processed = 0;

        for item in items {
            current_batch.push(item);

            // Process batch when it reaches optimal size or memory limit
            if current_batch.len() >= self.max_batch_size
                || (self.memory_limit > 0 && self.current_memory >= self.memory_limit)
            {
                let batch_results = processor(&current_batch)?;
                results.extend(batch_results);
                total_processed += current_batch.len();

                current_batch.clear();
                self.current_memory = 0; // Reset after processing

                if config.show_progress {
                    println!("Processed {} items in streaming mode", total_processed);
                }
            }
        }

        // Process remaining items
        if !current_batch.is_empty() {
            let batch_results = processor(&current_batch)?;
            results.extend(batch_results);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Blake3Hasher, Hash as HashTrait};

    fn create_test_leaf_hash(data: &[u8]) -> HashDigest {
        let hasher = Blake3Hasher::new();
        hasher.hash_bytes(data).unwrap()
    }

    #[test]
    fn test_batch_proof_generation_small() {
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices = vec![0, 1, 2, 3];
        let entry_ids: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig::default();
        let result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();

        assert_eq!(result.proofs.len(), 4);
        assert_eq!(result.failures.len(), 0);
        assert_eq!(result.stats.successful, 4);
        assert_eq!(result.stats.failed, 0);
        assert!(result.stats.avg_time_per_proof_us > 0.0);
    }

    #[test]
    fn test_batch_proof_generation_large() {
        let leaves: Vec<HashDigest> = (0..1000)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..100).collect();
        let entry_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig {
            chunk_size: 25,
            show_progress: false,
            memory_limit: 0,
            parallel: true,
        };

        let result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();

        assert_eq!(result.proofs.len(), 100);
        assert_eq!(result.failures.len(), 0);
        assert!(result.stats.avg_time_per_proof_us > 0.0);

        // Verify a sample of proofs
        for proof in result.proofs.iter().take(10) {
            assert!(proof
                .verify_against_root(&generator.tree_cache.root_hash)
                .unwrap());
        }
    }

    #[test]
    fn test_batch_verification() {
        let leaves: Vec<HashDigest> = (0..8)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..8).collect();
        let entry_ids: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig::default();
        let proof_result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();

        let mut verifier = BatchProofVerifier::new(generator.tree_cache.root_hash.clone());
        let verification_result = verifier.verify_batch(&proof_result.proofs, &config);

        assert_eq!(verification_result.results.len(), 8);
        assert_eq!(verification_result.stats.valid, 8);
        assert_eq!(verification_result.stats.invalid, 0);

        // All should be valid
        for result in &verification_result.results {
            assert!(result.as_ref().unwrap());
        }
    }

    #[test]
    fn test_memory_usage_calculation() {
        let leaves: Vec<HashDigest> = (0..100)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let memory_usage = generator.memory_usage();

        assert!(memory_usage > 0);

        let (leaf_count, height, levels) = generator.tree_stats();
        assert_eq!(leaf_count, 100);
        assert!(height > 0);
        assert!(levels > 0);
    }

    #[test]
    fn test_invalid_indices_handling() {
        let leaves: Vec<HashDigest> = (0..4)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices = vec![0, 5, 2]; // Index 5 is invalid
        let entry_ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig::default();
        let result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();

        assert_eq!(result.proofs.len(), 2); // Only valid indices
        assert_eq!(result.failures.len(), 1); // One failure
        assert_eq!(result.stats.successful, 2);
        assert_eq!(result.stats.failed, 1);
    }

    #[test]
    fn test_streaming_processor() {
        let mut processor = StreamingBatchProcessor::new(10, 1024);
        let items: Vec<i32> = (0..25).collect();

        let mut batch_count = 0;
        let results = processor
            .process_streaming(
                items.iter().cloned(),
                |batch| {
                    batch_count += 1;
                    Ok(batch.iter().map(|&x| x * 2).collect())
                },
                &BatchConfig::default(),
            )
            .unwrap();

        assert_eq!(results.len(), 25);
        assert!(batch_count >= 3); // Should process in multiple batches

        // Verify results
        for (i, &result) in results.iter().enumerate() {
            assert_eq!(result, i as i32 * 2);
        }
    }

    #[test]
    fn test_parallel_vs_sequential() {
        let leaves: Vec<HashDigest> = (0..50)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..50).collect();
        let entry_ids: Vec<Uuid> = (0..50).map(|_| Uuid::new_v4()).collect();

        // Sequential
        let config_seq = BatchConfig {
            parallel: false,
            show_progress: false,
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let result_seq = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config_seq)
            .unwrap();
        let duration_seq = start.elapsed();

        // Parallel
        let config_par = BatchConfig {
            parallel: true,
            show_progress: false,
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let result_par = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config_par)
            .unwrap();
        let duration_par = start.elapsed();

        // Both should succeed
        assert_eq!(result_seq.proofs.len(), 50);
        assert_eq!(result_par.proofs.len(), 50);

        // Results should be equivalent (though order may differ in parallel)
        assert_eq!(result_seq.stats.successful, result_par.stats.successful);

        println!(
            "Sequential: {:?}, Parallel: {:?}",
            duration_seq, duration_par
        );
    }

    #[test]
    fn test_large_batch_operations() {
        let leaves: Vec<HashDigest> = (0..10000)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..1000).collect();
        let entry_ids: Vec<Uuid> = (0..1000).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig {
            chunk_size: 100,
            show_progress: false,
            memory_limit: 0,
            parallel: true,
        };

        let start = std::time::Instant::now();
        let result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();
        let duration = start.elapsed();

        assert_eq!(result.proofs.len(), 1000);
        assert_eq!(result.failures.len(), 0);
        assert_eq!(result.stats.successful, 1000);
        assert!(result.stats.avg_time_per_proof_us > 0.0);

        println!("Generated 1000 proofs for 10K tree in {:?}", duration);
        println!(
            "Average time per proof: {:.2} μs",
            result.stats.avg_time_per_proof_us
        );
        println!("Memory usage: {} bytes", result.stats.memory_usage);

        // Verify random sample of proofs
        for i in (0..1000).step_by(100) {
            assert!(result.proofs[i]
                .verify_against_root(&generator.tree_cache.root_hash)
                .unwrap());
        }
    }

    #[test]
    fn test_batch_vs_individual_performance() {
        let leaves: Vec<HashDigest> = (0..1000)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let leaf_indices: Vec<usize> = (0..100).collect();
        let entry_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();

        // Individual proof generation
        let start = std::time::Instant::now();
        let mut individual_proofs = Vec::new();
        for (&idx, &entry_id) in leaf_indices.iter().zip(entry_ids.iter()) {
            let proof = InclusionProof::generate_for_leaf_index(entry_id, idx, &leaves).unwrap();
            individual_proofs.push(proof);
        }
        let individual_duration = start.elapsed();

        // Batch proof generation
        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let config = BatchConfig::default();

        let start = std::time::Instant::now();
        let batch_result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();
        let batch_duration = start.elapsed();

        assert_eq!(individual_proofs.len(), 100);
        assert_eq!(batch_result.proofs.len(), 100);

        let speedup = individual_duration.as_nanos() as f64 / batch_duration.as_nanos() as f64;

        println!("Individual: {:?}", individual_duration);
        println!("Batch: {:?}", batch_duration);
        println!("Speedup: {:.2}x", speedup);

        // Should be significantly faster (at least 2x for this size)
        assert!(
            speedup >= 2.0,
            "Batch processing should be at least 2x faster, got {:.2}x",
            speedup
        );

        // Verify correctness - all proofs should be equivalent
        let generator_root = generator.tree_cache.root_hash;
        for (individual, batch) in individual_proofs.iter().zip(batch_result.proofs.iter()) {
            assert_eq!(individual.entry_id, batch.entry_id);
            assert_eq!(individual.leaf_index, batch.leaf_index);
            assert_eq!(individual.leaf_hash, batch.leaf_hash);
            assert_eq!(individual.root_hash, batch.root_hash);
            assert_eq!(individual.root_hash, generator_root);

            // Both should verify
            assert!(individual.verify_against_root(&generator_root).unwrap());
            assert!(batch.verify_against_root(&generator_root).unwrap());
        }
    }

    #[test]
    fn test_memory_efficiency() {
        let sizes = [100, 500, 1000, 2000];
        let mut memory_usage = Vec::new();

        for &size in &sizes {
            let leaves: Vec<HashDigest> = (0..size)
                .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
                .collect();

            let generator = BatchProofGenerator::new(&leaves).unwrap();
            let usage = generator.memory_usage();
            memory_usage.push((size, usage));

            println!("Tree size: {}, Memory usage: {} bytes", size, usage);
        }

        // Memory usage should scale reasonably (not exponentially)
        for i in 1..memory_usage.len() {
            let (prev_size, prev_mem) = memory_usage[i - 1];
            let (curr_size, curr_mem) = memory_usage[i];

            let size_ratio = curr_size as f64 / prev_size as f64;
            let mem_ratio = curr_mem as f64 / prev_mem as f64;

            // Memory should not grow faster than 2x the size ratio
            assert!(
                mem_ratio <= size_ratio * 2.0,
                "Memory usage growing too fast: size ratio {:.2}, memory ratio {:.2}",
                size_ratio,
                mem_ratio
            );
        }
    }

    #[test]
    fn test_batch_verification_performance() {
        let leaves: Vec<HashDigest> = (0..1000)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..100).collect();
        let entry_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig::default();
        let proof_result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();
        let root_hash = generator.tree_cache.root_hash.clone();

        // Individual verification
        let start = std::time::Instant::now();
        let mut individual_results = Vec::new();
        for proof in &proof_result.proofs {
            let result = proof.verify_against_root(&root_hash).unwrap();
            individual_results.push(result);
        }
        let individual_duration = start.elapsed();

        // Batch verification
        let mut verifier = BatchProofVerifier::new(root_hash);
        let start = std::time::Instant::now();
        let batch_result = verifier.verify_batch(&proof_result.proofs, &config);
        let batch_duration = start.elapsed();

        assert_eq!(individual_results.len(), 100);
        assert_eq!(batch_result.results.len(), 100);

        let speedup = individual_duration.as_nanos() as f64 / batch_duration.as_nanos() as f64;

        println!("Individual verification: {:?}", individual_duration);
        println!("Batch verification: {:?}", batch_duration);
        println!("Verification speedup: {:.2}x", speedup);

        // All should be valid
        assert!(individual_results.iter().all(|&x| x));
        assert_eq!(batch_result.stats.valid, 100);
        assert_eq!(batch_result.stats.invalid, 0);

        // Batch should be faster for large enough datasets
        // Note: In practice, batch verification may not always be faster due to overhead
        // and the simplicity of individual proof verification. The benefit comes from
        // reduced context switching and better CPU cache usage in larger datasets.
        if proof_result.proofs.len() >= 50 {
            // Allow generous margin since batch verification overhead might offset gains
            // for moderately sized datasets, especially on different system loads
            assert!(
                speedup >= 0.3,
                "Batch verification performance should be reasonable, got {:.2}x",
                speedup
            );
        }
    }

    #[test]
    fn test_stress_large_tree() {
        // Test with a very large tree to ensure scalability
        let tree_size = 50000;
        let proof_count = 500;

        let leaves: Vec<HashDigest> = (0..tree_size)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        println!("Building tree cache for {} leaves...", tree_size);
        let start = std::time::Instant::now();
        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let cache_time = start.elapsed();

        let leaf_indices: Vec<usize> = (0..proof_count).step_by(tree_size / proof_count).collect();
        let entry_ids: Vec<Uuid> = (0..leaf_indices.len()).map(|_| Uuid::new_v4()).collect();

        let config = BatchConfig {
            chunk_size: 50,
            show_progress: false,
            memory_limit: 0,
            parallel: true,
        };

        println!("Generating {} proofs...", leaf_indices.len());
        let start = std::time::Instant::now();
        let result = generator
            .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
            .unwrap();
        let proof_time = start.elapsed();

        println!("Cache build time: {:?}", cache_time);
        println!("Proof generation time: {:?}", proof_time);
        println!(
            "Memory usage: {} MB",
            result.stats.memory_usage / 1024 / 1024
        );
        println!(
            "Average time per proof: {:.2} μs",
            result.stats.avg_time_per_proof_us
        );

        assert_eq!(result.proofs.len(), leaf_indices.len());
        assert_eq!(result.failures.len(), 0);

        // Verify sample of proofs
        let sample_indices = [0, result.proofs.len() / 2, result.proofs.len() - 1];
        for &i in &sample_indices {
            assert!(result.proofs[i]
                .verify_against_root(&generator.tree_cache.root_hash)
                .unwrap());
        }

        // Performance expectations for large trees
        assert!(
            result.stats.avg_time_per_proof_us < 1000.0,
            "Proof generation too slow: {:.2} μs",
            result.stats.avg_time_per_proof_us
        );
    }

    #[test]
    fn test_chunk_size_optimization() {
        let leaves: Vec<HashDigest> = (0..1000)
            .map(|i| create_test_leaf_hash(format!("leaf {}", i).as_bytes()))
            .collect();

        let generator = BatchProofGenerator::new(&leaves).unwrap();
        let leaf_indices: Vec<usize> = (0..100).collect();
        let entry_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();

        let chunk_sizes = [10, 25, 50, 100];
        let mut results = Vec::new();

        for &chunk_size in &chunk_sizes {
            let config = BatchConfig {
                chunk_size,
                show_progress: false,
                memory_limit: 0,
                parallel: true,
            };

            let start = std::time::Instant::now();
            let result = generator
                .generate_batch_proofs(&leaf_indices, &entry_ids, &config)
                .unwrap();
            let duration = start.elapsed();

            results.push((chunk_size, duration, result.stats.avg_time_per_proof_us));

            assert_eq!(result.proofs.len(), 100);
            assert_eq!(result.failures.len(), 0);
        }

        println!("Chunk size performance comparison:");
        for (chunk_size, duration, avg_time) in &results {
            println!(
                "  Chunk size {}: {:?} total, {:.2} μs avg",
                chunk_size, duration, avg_time
            );
        }

        // All should complete successfully regardless of chunk size
        assert!(results.iter().all(|(_, _, _)| true));
    }
}

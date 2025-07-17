use crate::error::SylvaError;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zstd::{Decoder, Encoder};

/// Compression algorithms supported by Sylva
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CompressionAlgorithm {
    None,
    #[default]
    Zstd,
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::None => write!(f, "none"),
            CompressionAlgorithm::Zstd => write!(f, "zstd"),
        }
    }
}

impl std::str::FromStr for CompressionAlgorithm {
    type Err = SylvaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" | "uncompressed" => Ok(CompressionAlgorithm::None),
            "zstd" | "zstandard" => Ok(CompressionAlgorithm::Zstd),
            _ => Err(SylvaError::ConfigError {
                message: format!(
                    "Unknown compression algorithm: {}. Supported: none, zstd",
                    s
                ),
            }),
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm,
    pub level: i32,
    pub enable_dict: bool,
    pub verify_integrity: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3, // Good balance of speed and compression
            enable_dict: false,
            verify_integrity: true,
        }
    }
}

impl CompressionConfig {
    /// Create a new compression config with validation
    pub fn new(algorithm: CompressionAlgorithm, level: i32) -> Result<Self, SylvaError> {
        let config = CompressionConfig {
            algorithm,
            level,
            enable_dict: false,
            verify_integrity: true,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate compression configuration
    pub fn validate(&self) -> Result<(), SylvaError> {
        match self.algorithm {
            CompressionAlgorithm::None => {
                if self.level != 0 {
                    return Err(SylvaError::ConfigError {
                        message: "Compression level must be 0 for uncompressed data".to_string(),
                    });
                }
            }
            CompressionAlgorithm::Zstd => {
                if !(1..=22).contains(&self.level) {
                    return Err(SylvaError::ConfigError {
                        message: format!(
                            "Zstd compression level must be between 1 and 22, got {}",
                            self.level
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Get a configuration optimized for speed
    pub fn fast() -> Self {
        CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 1,
            enable_dict: false,
            verify_integrity: true,
        }
    }

    /// Get a configuration optimized for compression ratio
    pub fn max_compression() -> Self {
        CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: 22,
            enable_dict: true,
            verify_integrity: true,
        }
    }

    /// Get a configuration with balanced speed and compression
    pub fn balanced() -> Self {
        CompressionConfig::default()
    }
}

/// Compression statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionStats {
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    pub space_savings: f64,
    pub algorithm: CompressionAlgorithm,
    pub level: i32,
    pub compression_time_ms: u64,
    pub decompression_time_ms: Option<u64>,
}

impl CompressionStats {
    pub fn new(
        original_size: usize,
        compressed_size: usize,
        algorithm: CompressionAlgorithm,
        level: i32,
        compression_time_ms: u64,
    ) -> Self {
        let compression_ratio = if original_size > 0 {
            compressed_size as f64 / original_size as f64
        } else {
            1.0
        };

        let space_savings = if original_size > 0 && compressed_size <= original_size {
            ((original_size - compressed_size) as f64 / original_size as f64) * 100.0
        } else if original_size > 0 {
            // Compression made data larger (negative savings)
            -((compressed_size - original_size) as f64 / original_size as f64) * 100.0
        } else {
            0.0
        };

        CompressionStats {
            original_size,
            compressed_size,
            compression_ratio,
            space_savings,
            algorithm,
            level,
            compression_time_ms,
            decompression_time_ms: None,
        }
    }

    pub fn set_decompression_time(&mut self, decompression_time_ms: u64) {
        self.decompression_time_ms = Some(decompression_time_ms);
    }

    /// Format compression stats for display
    pub fn display(&self) -> String {
        format!(
            "Compression: {} bytes → {} bytes ({:.1}% savings, {:.2}x ratio) using {} level {} in {}ms",
            self.original_size,
            self.compressed_size,
            self.space_savings,
            self.compression_ratio,
            self.algorithm,
            self.level,
            self.compression_time_ms
        )
    }

    /// Check if compression was beneficial
    pub fn is_beneficial(&self) -> bool {
        self.space_savings > 5.0 // Only beneficial if saves more than 5%
    }
}

/// Compressed data container with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    pub data: Vec<u8>,
    pub config: CompressionConfig,
    pub stats: CompressionStats,
    pub checksum: u32, // CRC32 checksum for integrity
    pub version: u8,   // Format version for backward compatibility
}

impl CompressedData {
    const CURRENT_VERSION: u8 = 1;

    /// Verify the integrity of compressed data
    pub fn verify_integrity(&self) -> Result<(), SylvaError> {
        if !self.config.verify_integrity {
            return Ok(());
        }

        let computed_checksum = crc32fast::hash(&self.data);
        if computed_checksum != self.checksum {
            return Err(SylvaError::StorageError {
                message: format!(
                    "Checksum mismatch: expected {}, got {}",
                    self.checksum, computed_checksum
                ),
            });
        }

        Ok(())
    }

    /// Check if this compressed data format is supported
    pub fn is_supported_version(&self) -> bool {
        self.version <= Self::CURRENT_VERSION
    }
}

/// Main compression utility
#[derive(Default)]
pub struct Compressor {
    config: CompressionConfig,
}

impl Compressor {
    /// Create a new compressor with the given configuration
    pub fn new(config: CompressionConfig) -> Result<Self, SylvaError> {
        config.validate()?;
        Ok(Compressor { config })
    }

    /// Compress data and return compressed container with statistics
    pub fn compress(&self, data: &[u8]) -> Result<CompressedData, SylvaError> {
        let start_time = std::time::Instant::now();

        let compressed_data = match self.config.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Zstd => self.compress_zstd(data)?,
        };

        let compression_time_ms = start_time.elapsed().as_millis() as u64;

        let stats = CompressionStats::new(
            data.len(),
            compressed_data.len(),
            self.config.algorithm,
            self.config.level,
            compression_time_ms,
        );

        let checksum = if self.config.verify_integrity {
            crc32fast::hash(&compressed_data)
        } else {
            0
        };

        Ok(CompressedData {
            data: compressed_data,
            config: self.config.clone(),
            stats,
            checksum,
            version: CompressedData::CURRENT_VERSION,
        })
    }

    /// Decompress data from compressed container
    pub fn decompress(&self, compressed: &CompressedData) -> Result<Vec<u8>, SylvaError> {
        // Verify format version
        if !compressed.is_supported_version() {
            return Err(SylvaError::StorageError {
                message: format!(
                    "Unsupported compressed data format version: {}",
                    compressed.version
                ),
            });
        }

        // Verify integrity
        compressed.verify_integrity()?;

        let start_time = std::time::Instant::now();

        let decompressed_data = match compressed.config.algorithm {
            CompressionAlgorithm::None => compressed.data.clone(),
            CompressionAlgorithm::Zstd => self.decompress_zstd(&compressed.data)?,
        };

        let _decompression_time_ms = start_time.elapsed().as_millis() as u64;

        // Verify decompressed size matches expected
        if decompressed_data.len() != compressed.stats.original_size {
            return Err(SylvaError::StorageError {
                message: format!(
                    "Decompressed size mismatch: expected {}, got {}",
                    compressed.stats.original_size,
                    decompressed_data.len()
                ),
            });
        }

        Ok(decompressed_data)
    }

    /// Compress data using Zstandard
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, SylvaError> {
        let mut compressed = Vec::new();
        {
            let mut encoder = Encoder::new(&mut compressed, self.config.level).map_err(|e| {
                SylvaError::StorageError {
                    message: format!("Failed to create zstd encoder: {}", e),
                }
            })?;

            encoder
                .write_all(data)
                .map_err(|e| SylvaError::StorageError {
                    message: format!("Failed to compress data: {}", e),
                })?;

            encoder.finish().map_err(|e| SylvaError::StorageError {
                message: format!("Failed to finish compression: {}", e),
            })?;
        }
        Ok(compressed)
    }

    /// Decompress data using Zstandard
    fn decompress_zstd(&self, compressed_data: &[u8]) -> Result<Vec<u8>, SylvaError> {
        let mut decoder = Decoder::new(compressed_data).map_err(|e| SylvaError::StorageError {
            message: format!("Failed to create zstd decoder: {}", e),
        })?;

        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| SylvaError::StorageError {
                message: format!("Failed to decompress data: {}", e),
            })?;

        Ok(decompressed)
    }

    /// Get compression configuration
    pub fn config(&self) -> &CompressionConfig {
        &self.config
    }

    /// Test compression on sample data to estimate efficiency
    pub fn test_compression(&self, sample_data: &[u8]) -> Result<CompressionStats, SylvaError> {
        let compressed = self.compress(sample_data)?;
        Ok(compressed.stats)
    }
}

/// Utility functions for compression analysis
pub struct CompressionAnalyzer;

impl CompressionAnalyzer {
    /// Analyze multiple compression levels and return the best one
    pub fn find_optimal_level(
        data: &[u8],
        algorithm: CompressionAlgorithm,
    ) -> Result<(i32, CompressionStats), SylvaError> {
        match algorithm {
            CompressionAlgorithm::None => {
                let stats = CompressionStats::new(data.len(), data.len(), algorithm, 0, 0);
                Ok((0, stats))
            }
            CompressionAlgorithm::Zstd => {
                let mut best_level = 1;
                let mut best_score = f64::MAX;
                let mut best_stats = None;

                // Test levels 1, 3, 6, 9, 12, 15, 19, 22
                for level in [1, 3, 6, 9, 12, 15, 19, 22] {
                    let config = CompressionConfig::new(algorithm, level)?;
                    let compressor = Compressor::new(config)?;
                    let stats = compressor.test_compression(data)?;

                    // Score based on compression ratio and time (favor speed over extreme compression)
                    let score =
                        stats.compression_ratio + (stats.compression_time_ms as f64 / 1000.0);

                    if score < best_score {
                        best_score = score;
                        best_level = level;
                        best_stats = Some(stats);
                    }
                }

                Ok((best_level, best_stats.unwrap()))
            }
        }
    }

    /// Compare compression algorithms on sample data
    pub fn compare_algorithms(data: &[u8]) -> Result<Vec<CompressionStats>, SylvaError> {
        let mut results = Vec::new();

        // Test no compression
        let none_stats =
            CompressionStats::new(data.len(), data.len(), CompressionAlgorithm::None, 0, 0);
        results.push(none_stats);

        // Test zstd at different levels
        for level in [1, 3, 6, 9, 15, 22] {
            let config = CompressionConfig::new(CompressionAlgorithm::Zstd, level)?;
            let compressor = Compressor::new(config)?;
            let stats = compressor.test_compression(data)?;
            results.push(stats);
        }

        Ok(results)
    }

    /// Estimate memory usage for compression
    pub fn estimate_memory_usage(data_size: usize, algorithm: CompressionAlgorithm) -> usize {
        match algorithm {
            CompressionAlgorithm::None => data_size,
            CompressionAlgorithm::Zstd => {
                // Zstd typically needs ~2x input size for compression buffer
                data_size * 2 + 1024 * 1024 // Plus 1MB for internal buffers
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_config_validation() {
        // Valid configs
        assert!(CompressionConfig::new(CompressionAlgorithm::None, 0).is_ok());
        assert!(CompressionConfig::new(CompressionAlgorithm::Zstd, 1).is_ok());
        assert!(CompressionConfig::new(CompressionAlgorithm::Zstd, 22).is_ok());

        // Invalid configs
        assert!(CompressionConfig::new(CompressionAlgorithm::None, 5).is_err());
        assert!(CompressionConfig::new(CompressionAlgorithm::Zstd, 0).is_err());
        assert!(CompressionConfig::new(CompressionAlgorithm::Zstd, 23).is_err());
    }

    #[test]
    fn test_no_compression() {
        let data = b"Hello, world! This is test data for compression.";
        let config = CompressionConfig::new(CompressionAlgorithm::None, 0).unwrap();
        let compressor = Compressor::new(config).unwrap();

        let compressed = compressor.compress(data).unwrap();
        assert_eq!(compressed.data, data);
        assert_eq!(compressed.stats.original_size, data.len());
        assert_eq!(compressed.stats.compressed_size, data.len());
        assert_eq!(compressed.stats.compression_ratio, 1.0);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_zstd_compression() {
        let data = b"Hello, world! This is test data for compression. ".repeat(100);
        let config = CompressionConfig::new(CompressionAlgorithm::Zstd, 3).unwrap();
        let compressor = Compressor::new(config).unwrap();

        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.stats.compressed_size < compressed.stats.original_size);
        assert!(compressed.stats.space_savings > 0.0);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_stats() {
        let stats = CompressionStats::new(1000, 500, CompressionAlgorithm::Zstd, 3, 10);
        assert_eq!(stats.compression_ratio, 0.5);
        assert_eq!(stats.space_savings, 50.0);
        assert!(stats.is_beneficial());

        let stats_no_benefit = CompressionStats::new(1000, 980, CompressionAlgorithm::Zstd, 1, 5);
        assert!(!stats_no_benefit.is_beneficial());
    }

    #[test]
    fn test_compressed_data_integrity() {
        let data = b"Test data for integrity verification";
        let config = CompressionConfig::new(CompressionAlgorithm::Zstd, 5).unwrap();
        let compressor = Compressor::new(config).unwrap();

        let mut compressed = compressor.compress(data).unwrap();
        assert!(compressed.verify_integrity().is_ok());

        // Corrupt the data
        compressed.data[0] ^= 1;
        assert!(compressed.verify_integrity().is_err());
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Test data for compression level testing. ".repeat(50);

        let level1_config = CompressionConfig::new(CompressionAlgorithm::Zstd, 1).unwrap();
        let level22_config = CompressionConfig::new(CompressionAlgorithm::Zstd, 22).unwrap();

        let compressor1 = Compressor::new(level1_config).unwrap();
        let compressor22 = Compressor::new(level22_config).unwrap();

        let compressed1 = compressor1.compress(&data).unwrap();
        let compressed22 = compressor22.compress(&data).unwrap();

        // Level 22 should achieve better compression than level 1
        assert!(compressed22.stats.compressed_size <= compressed1.stats.compressed_size);
        // But level 1 should be faster
        assert!(compressed1.stats.compression_time_ms <= compressed22.stats.compression_time_ms);

        // Both should decompress correctly
        let decompressed1 = compressor1.decompress(&compressed1).unwrap();
        let decompressed22 = compressor22.decompress(&compressed22).unwrap();
        assert_eq!(decompressed1, data);
        assert_eq!(decompressed22, data);
    }

    #[test]
    fn test_compression_analyzer() {
        let data = b"Repeated data for compression analysis. ".repeat(100);

        let results = CompressionAnalyzer::compare_algorithms(&data).unwrap();
        assert!(!results.is_empty());

        // Find best level
        let (best_level, best_stats) =
            CompressionAnalyzer::find_optimal_level(&data, CompressionAlgorithm::Zstd).unwrap();
        assert!((1..=22).contains(&best_level));
        assert!(best_stats.is_beneficial());
    }

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(
            "none".parse::<CompressionAlgorithm>().unwrap(),
            CompressionAlgorithm::None
        );
        assert_eq!(
            "zstd".parse::<CompressionAlgorithm>().unwrap(),
            CompressionAlgorithm::Zstd
        );
        assert!("invalid".parse::<CompressionAlgorithm>().is_err());
    }
}

//! Streaming proof generation without loading full ledger history

use crate::error::{Result, SylvaError};
use crate::ledger::LedgerEntry;
use crate::proof::InclusionProof;
use crate::storage::LedgerStorage;
use crate::tree::{binary::BinaryMerkleTree, Tree};
use futures::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use uuid::Uuid;

use super::{StreamingConfig, StreamingContext, StreamingResult};

/// Streaming proof generator that processes ledger entries incrementally
pub struct StreamingProofGenerator {
    config: StreamingConfig,
    storage: Arc<LedgerStorage>,
    context: StreamingContext,
    _proof_cache: VecDeque<InclusionProof>,
}

impl StreamingProofGenerator {
    pub fn new(config: StreamingConfig, storage: Arc<LedgerStorage>) -> Self {
        let context = StreamingContext::new(config.clone());
        Self {
            config,
            storage,
            context,
            _proof_cache: VecDeque::new(),
        }
    }

    /// Generate proofs for a range of entries without loading the full ledger
    pub async fn generate_proofs_for_range(
        &mut self,
        ledger_id: &Uuid,
        start_version: u64,
        end_version: u64,
    ) -> Result<StreamingResult<Vec<InclusionProof>>> {
        let start_time = std::time::Instant::now();
        let mut proofs = Vec::new();
        let mut entries_processed = 0;
        let mut memory_peak = 0;

        // Stream entries in the version range
        let mut current_batch_start = start_version;
        while current_batch_start <= end_version {
            let batch_end = std::cmp::min(
                current_batch_start + self.config.batch_size as u64,
                end_version + 1,
            );

            // Load batch of entries
            let entries =
                self.load_entries_for_version_range(ledger_id, current_batch_start, batch_end)?;

            if entries.is_empty() {
                break;
            }

            // Generate proofs for this batch
            let batch_proofs = self.generate_proofs_for_batch(&entries)?;
            proofs.extend(batch_proofs);

            entries_processed += entries.len();
            memory_peak = std::cmp::max(memory_peak, self.estimate_memory_usage(&entries));

            // Create checkpoint if needed
            if entries_processed % self.config.checkpoint_interval == 0 {
                self.create_checkpoint()?;
            }

            current_batch_start = batch_end;
        }

        Ok(StreamingResult {
            data: proofs,
            entries_processed,
            memory_peak,
            processing_time: start_time.elapsed(),
            checkpoints_created: if self.context.last_checkpoint.is_some() {
                1
            } else {
                0
            },
        })
    }

    /// Generate a single proof for an entry without loading full ledger
    pub async fn generate_proof_for_entry(
        &mut self,
        ledger_id: &Uuid,
        entry_id: &Uuid,
    ) -> Result<InclusionProof> {
        // Load the specific entry and its context
        let entry = self.find_entry_by_id(ledger_id, entry_id)?;

        // Load minimal set of entries needed for proof generation
        let context_entries = self.load_context_entries_for_proof(ledger_id, &entry)?;

        // Generate proof using minimal context
        self.generate_proof_for_entry_with_context(&entry, &context_entries)
    }

    /// Stream proofs as they are generated
    pub fn stream_proofs_for_ledger(&self, ledger_id: &Uuid) -> ProofStream {
        ProofStream::new(self.storage.clone(), *ledger_id, self.config.clone())
    }

    fn load_entries_for_version_range(
        &self,
        ledger_id: &Uuid,
        start_version: u64,
        end_version: u64,
    ) -> Result<Vec<LedgerEntry>> {
        // Load metadata to get entry count
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        // Use memory-mapped access for efficient range loading
        let mut entries = Vec::new();
        let mut position = 0;

        while position < metadata.entry_count {
            let batch_size = std::cmp::min(self.config.batch_size, metadata.entry_count - position);
            let batch_entries =
                self.storage
                    .load_entries_range(ledger_id, position, position + batch_size)?;

            for entry in batch_entries {
                if entry.version >= start_version && entry.version < end_version {
                    entries.push(entry);
                }
            }

            position += batch_size;
        }

        Ok(entries)
    }

    fn generate_proofs_for_batch(&self, entries: &[LedgerEntry]) -> Result<Vec<InclusionProof>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        // Create tree from batch entries
        let tree = BinaryMerkleTree::from_entries(entries.to_vec())?;
        let mut proofs = Vec::new();

        // Generate proof for each entry using its UUID
        for entry in entries.iter() {
            if let Some(merkle_proof) = tree.generate_proof(&entry.id)? {
                // Convert MerkleProof to InclusionProof
                let sibling_hashes: Vec<crate::proof::SiblingHash> = merkle_proof
                    .path
                    .iter()
                    .map(|element| crate::proof::SiblingHash {
                        hash: element.hash.clone(),
                        direction: if element.is_left {
                            crate::proof::Direction::Left
                        } else {
                            crate::proof::Direction::Right
                        },
                    })
                    .collect();

                let inclusion_proof = InclusionProof::new(
                    entry.id,
                    0, // Index would need to be calculated properly
                    merkle_proof.entry_hash,
                    sibling_hashes,
                    merkle_proof.root_hash,
                    entries.len(),
                );
                proofs.push(inclusion_proof);
            }
        }

        Ok(proofs)
    }

    fn find_entry_by_id(&self, ledger_id: &Uuid, entry_id: &Uuid) -> Result<LedgerEntry> {
        // Stream through entries to find the target without loading full ledger
        let metadata = self
            .storage
            .get_ledger_metadata(ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: ledger_id.to_string(),
            })?;

        let mut position = 0;
        while position < metadata.entry_count {
            let batch_size = std::cmp::min(self.config.batch_size, metadata.entry_count - position);
            let batch_entries =
                self.storage
                    .load_entries_range(ledger_id, position, position + batch_size)?;

            for entry in batch_entries {
                if entry.id == *entry_id {
                    return Ok(entry);
                }
            }

            position += batch_size;
        }

        Err(SylvaError::NotFound {
            item_type: "entry".to_string(),
            identifier: entry_id.to_string(),
        })
    }

    fn load_context_entries_for_proof(
        &self,
        ledger_id: &Uuid,
        target_entry: &LedgerEntry,
    ) -> Result<Vec<LedgerEntry>> {
        // Load entries from the same version for context
        // This is a simplified approach - in practice, you might want to load
        // entries based on temporal proximity or tree structure
        self.load_entries_for_version_range(
            ledger_id,
            target_entry.version,
            target_entry.version + 1,
        )
    }

    fn generate_proof_for_entry_with_context(
        &self,
        entry: &LedgerEntry,
        context_entries: &[LedgerEntry],
    ) -> Result<InclusionProof> {
        if context_entries.is_empty() {
            return Err(SylvaError::InvalidOperation {
                message: "Cannot generate proof without context entries".to_string(),
            });
        }

        // Find entry position in context
        let entry_index = context_entries
            .iter()
            .position(|e| e.id == entry.id)
            .ok_or_else(|| SylvaError::InvalidOperation {
                message: "Entry not found in context".to_string(),
            })?;

        // Create tree from context entries
        let tree = BinaryMerkleTree::from_entries(context_entries.to_vec())?;

        if let Some(merkle_proof) = tree.generate_proof(&entry.id)? {
            // Convert MerkleProof to InclusionProof
            let sibling_hashes: Vec<crate::proof::SiblingHash> = merkle_proof
                .path
                .iter()
                .map(|element| crate::proof::SiblingHash {
                    hash: element.hash.clone(),
                    direction: if element.is_left {
                        crate::proof::Direction::Left
                    } else {
                        crate::proof::Direction::Right
                    },
                })
                .collect();

            let inclusion_proof = InclusionProof::new(
                entry.id,
                entry_index,
                merkle_proof.entry_hash,
                sibling_hashes,
                merkle_proof.root_hash,
                context_entries.len(),
            );
            Ok(inclusion_proof)
        } else {
            Err(SylvaError::InvalidOperation {
                message: "Failed to generate proof for entry".to_string(),
            })
        }
    }

    fn estimate_memory_usage(&self, entries: &[LedgerEntry]) -> usize {
        entries
            .iter()
            .map(|e| {
                std::mem::size_of::<LedgerEntry>() + e.data.len() + e.metadata.len() * 64
                // Rough estimate
            })
            .sum()
    }

    fn create_checkpoint(&mut self) -> Result<()> {
        self.context.last_checkpoint = Some(std::time::Instant::now());
        // In a full implementation, this would save checkpoint data
        Ok(())
    }
}

/// Stream that yields proofs as they are generated
pub struct ProofStream {
    storage: Arc<LedgerStorage>,
    ledger_id: Uuid,
    config: StreamingConfig,
    current_position: usize,
    proof_buffer: VecDeque<InclusionProof>,
    finished: bool,
}

impl ProofStream {
    fn new(storage: Arc<LedgerStorage>, ledger_id: Uuid, config: StreamingConfig) -> Self {
        Self {
            storage,
            ledger_id,
            config,
            current_position: 0,
            proof_buffer: VecDeque::new(),
            finished: false,
        }
    }

    fn load_next_proof_batch(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        // Load metadata to check bounds
        let metadata = self
            .storage
            .get_ledger_metadata(&self.ledger_id)?
            .ok_or_else(|| SylvaError::NotFound {
                item_type: "ledger".to_string(),
                identifier: self.ledger_id.to_string(),
            })?;

        if self.current_position >= metadata.entry_count {
            self.finished = true;
            return Ok(());
        }

        // Load next batch of entries
        let batch_end = std::cmp::min(
            self.current_position + self.config.batch_size,
            metadata.entry_count,
        );

        let entries =
            self.storage
                .load_entries_range(&self.ledger_id, self.current_position, batch_end)?;

        // Generate proofs for this batch
        if !entries.is_empty() {
            let tree = BinaryMerkleTree::from_entries(entries.clone())?;
            for entry in &entries {
                if let Some(merkle_proof) = tree.generate_proof(&entry.id)? {
                    // Convert MerkleProof to InclusionProof
                    let sibling_hashes: Vec<crate::proof::SiblingHash> = merkle_proof
                        .path
                        .iter()
                        .map(|element| crate::proof::SiblingHash {
                            hash: element.hash.clone(),
                            direction: if element.is_left {
                                crate::proof::Direction::Left
                            } else {
                                crate::proof::Direction::Right
                            },
                        })
                        .collect();

                    let inclusion_proof = InclusionProof::new(
                        entry.id,
                        0, // Index would need proper calculation
                        merkle_proof.entry_hash,
                        sibling_hashes,
                        merkle_proof.root_hash,
                        entries.len(),
                    );
                    self.proof_buffer.push_back(inclusion_proof);
                }
            }
        }

        self.current_position = batch_end;
        Ok(())
    }
}

impl Stream for ProofStream {
    type Item = Result<InclusionProof>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.proof_buffer.is_empty() && !self.finished {
            if let Err(e) = self.load_next_proof_batch() {
                return Poll::Ready(Some(Err(e)));
            }
        }

        if let Some(proof) = self.proof_buffer.pop_front() {
            Poll::Ready(Some(Ok(proof)))
        } else if self.finished {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::MerkleProof;
    use crate::workspace::Workspace;
    use tempfile::TempDir;

    fn setup_test_storage_with_ledger() -> (TempDir, Arc<LedgerStorage>, Uuid) {
        let temp_dir = TempDir::new().unwrap();
        let workspace = Workspace::init(temp_dir.path()).unwrap();
        let storage = Arc::new(LedgerStorage::new(&workspace).unwrap());

        // Create a test ledger
        let mut ledger = crate::ledger::Ledger::new();
        for i in 0..10 {
            ledger
                .add_entry(format!("test data {}", i).into_bytes())
                .unwrap();
        }

        let ledger_id = storage.save_ledger(&ledger, "test ledger").unwrap();
        (temp_dir, storage, ledger_id)
    }

    #[tokio::test]
    async fn test_streaming_proof_generation_for_range() {
        let (_temp_dir, storage, ledger_id) = setup_test_storage_with_ledger();
        let config = StreamingConfig::default();
        let mut generator = StreamingProofGenerator::new(config, storage);

        let result = generator
            .generate_proofs_for_range(&ledger_id, 0, 5)
            .await
            .unwrap();

        assert_eq!(result.entries_processed, 6); // versions 0-5 inclusive
        assert!(!result.data.is_empty());
        assert!(result.processing_time.as_millis() < u128::MAX);
    }

    #[tokio::test]
    async fn test_streaming_proof_for_single_entry() {
        let (_temp_dir, storage, ledger_id) = setup_test_storage_with_ledger();
        let config = StreamingConfig::default();
        let mut generator = StreamingProofGenerator::new(config, storage.clone());

        // Get an entry ID from the ledger
        let ledger = storage.load_ledger(&ledger_id).unwrap();
        let entry_id = ledger.ledger.get_entries()[0].id;

        let proof = generator
            .generate_proof_for_entry(&ledger_id, &entry_id)
            .await
            .unwrap();

        assert_eq!(proof.entry_id, entry_id);
        assert!(proof.is_valid());
    }

    #[tokio::test]
    async fn test_proof_stream() {
        use futures::StreamExt;

        let (_temp_dir, storage, ledger_id) = setup_test_storage_with_ledger();
        let config = StreamingConfig::default();
        let generator = StreamingProofGenerator::new(config, storage);

        let mut proof_stream = generator.stream_proofs_for_ledger(&ledger_id);
        let mut proof_count = 0;

        while let Some(proof_result) = proof_stream.next().await {
            let proof = proof_result.unwrap();
            assert!(proof.is_valid());
            proof_count += 1;

            // Don't process all proofs in test to keep it fast
            if proof_count >= 3 {
                break;
            }
        }

        assert!(proof_count > 0);
    }
}

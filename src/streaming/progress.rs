//! Progress reporting for long-running streaming operations

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};

/// Progress callback function type
pub type ProgressCallback = Arc<dyn Fn(ProgressUpdate) + Send + Sync>;

/// Progress update information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// Unique operation ID
    pub operation_id: String,
    /// Current step in the operation
    pub current_step: usize,
    /// Total number of steps (if known)
    pub total_steps: Option<usize>,
    /// Number of entries processed
    pub entries_processed: usize,
    /// Current memory usage in bytes
    pub memory_usage: usize,
    /// Processing rate (entries per second)
    pub processing_rate: f64,
    /// Estimated time remaining
    pub eta_seconds: Option<f64>,
    /// Progress percentage (0.0-100.0)
    pub progress_percentage: f64,
    /// Current phase of operation
    pub phase: ProgressPhase,
    /// Optional status message
    pub message: Option<String>,
    /// Elapsed time since operation start
    pub elapsed_time: Duration,
    /// Throughput metrics
    pub throughput: ThroughputMetrics,
}

/// Different phases of streaming operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressPhase {
    /// Initializing the operation
    Initializing,
    /// Loading data from storage
    Loading,
    /// Processing entries
    Processing,
    /// Generating proofs
    ProofGeneration,
    /// Buffering data
    Buffering,
    /// Writing results
    Writing,
    /// Finalizing operation
    Finalizing,
    /// Operation completed
    Completed,
    /// Operation failed
    Failed(String),
}

/// Throughput metrics for performance monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetrics {
    /// Entries processed per second
    pub entries_per_second: f64,
    /// Bytes processed per second
    pub bytes_per_second: f64,
    /// Peak memory usage during operation
    pub peak_memory_bytes: usize,
    /// Average memory usage
    pub avg_memory_bytes: usize,
    /// Number of buffer flushes
    pub buffer_flushes: usize,
    /// Time spent in different phases
    pub phase_times: std::collections::HashMap<String, Duration>,
}

impl Default for ThroughputMetrics {
    fn default() -> Self {
        Self {
            entries_per_second: 0.0,
            bytes_per_second: 0.0,
            peak_memory_bytes: 0,
            avg_memory_bytes: 0,
            buffer_flushes: 0,
            phase_times: std::collections::HashMap::new(),
        }
    }
}

/// Progress reporter for streaming operations
#[derive(Clone)]
pub struct ProgressReporter {
    operation_id: String,
    start_time: Instant,
    last_update_time: Instant,
    entries_processed: usize,
    bytes_processed: usize,
    total_steps: Option<usize>,
    current_step: usize,
    current_phase: ProgressPhase,
    memory_samples: Vec<usize>,
    throughput: ThroughputMetrics,
    callbacks: Vec<ProgressCallback>,
    update_interval: Duration,
    broadcast_sender: Option<broadcast::Sender<ProgressUpdate>>,
    phase_start_times: std::collections::HashMap<String, Instant>,
}

impl ProgressReporter {
    /// Create a new progress reporter
    pub fn new(operation_id: String) -> Self {
        let now = Instant::now();
        let mut phase_start_times = std::collections::HashMap::new();
        phase_start_times.insert("Initializing".to_string(), now);

        Self {
            operation_id,
            start_time: now,
            last_update_time: now,
            entries_processed: 0,
            bytes_processed: 0,
            total_steps: None,
            current_step: 0,
            current_phase: ProgressPhase::Initializing,
            memory_samples: Vec::new(),
            throughput: ThroughputMetrics::default(),
            callbacks: Vec::new(),
            update_interval: Duration::from_millis(500), // Update every 500ms
            broadcast_sender: None,
            phase_start_times,
        }
    }

    /// Create a progress reporter with broadcast channel
    pub fn with_broadcast(
        operation_id: String,
        buffer_size: usize,
    ) -> (Self, broadcast::Receiver<ProgressUpdate>) {
        let (tx, rx) = broadcast::channel(buffer_size);
        let mut reporter = Self::new(operation_id);
        reporter.broadcast_sender = Some(tx);
        (reporter, rx)
    }

    /// Set total number of steps
    pub fn set_total_steps(&mut self, total: usize) {
        self.total_steps = Some(total);
    }

    /// Set update interval
    pub fn set_update_interval(&mut self, interval: Duration) {
        self.update_interval = interval;
    }

    /// Add a progress callback
    pub fn add_callback(&mut self, callback: ProgressCallback) {
        self.callbacks.push(callback);
    }

    /// Update progress with entry count
    pub fn update_entries(&mut self, entries_processed: usize, bytes_processed: usize) {
        self.entries_processed += entries_processed;
        self.bytes_processed += bytes_processed;
        self.try_send_update();
    }

    /// Update current step
    pub fn update_step(&mut self, step: usize) {
        self.current_step = step;
        self.try_send_update();
    }

    /// Update memory usage
    pub fn update_memory(&mut self, memory_bytes: usize) {
        self.memory_samples.push(memory_bytes);
        self.throughput.peak_memory_bytes = self.throughput.peak_memory_bytes.max(memory_bytes);

        // Keep only recent samples for average calculation
        if self.memory_samples.len() > 100 {
            self.memory_samples.remove(0);
        }

        self.throughput.avg_memory_bytes = if self.memory_samples.is_empty() {
            0
        } else {
            self.memory_samples.iter().sum::<usize>() / self.memory_samples.len()
        };
    }

    /// Update buffer flush count
    pub fn update_buffer_flushes(&mut self, count: usize) {
        self.throughput.buffer_flushes += count;
    }

    /// Set current phase
    pub fn set_phase(&mut self, phase: ProgressPhase) {
        // Record time spent in previous phase
        if let Some(phase_start) = self
            .phase_start_times
            .get(&format!("{:?}", self.current_phase))
        {
            let phase_duration = Instant::now().duration_since(*phase_start);
            self.throughput
                .phase_times
                .insert(format!("{:?}", self.current_phase), phase_duration);
        }

        self.current_phase = phase;
        self.phase_start_times
            .insert(format!("{:?}", self.current_phase), Instant::now());
        self.force_send_update();
    }

    /// Set status message
    pub fn set_message(&mut self, message: String) {
        let update = self.create_progress_update(Some(message));
        self.send_update(update);
    }

    /// Mark operation as completed
    pub fn complete(&mut self) {
        self.set_phase(ProgressPhase::Completed);
        self.force_send_update();
    }

    /// Mark operation as failed
    pub fn fail(&mut self, error: String) {
        self.set_phase(ProgressPhase::Failed(error));
        self.force_send_update();
    }

    /// Get current progress statistics
    pub fn get_stats(&self) -> ProgressStats {
        let elapsed = self.start_time.elapsed();
        let entries_per_second = if elapsed.as_secs_f64() > 0.0 {
            self.entries_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        ProgressStats {
            operation_id: self.operation_id.clone(),
            entries_processed: self.entries_processed,
            bytes_processed: self.bytes_processed,
            elapsed_time: elapsed,
            entries_per_second,
            current_phase: self.current_phase.clone(),
            peak_memory_bytes: self.throughput.peak_memory_bytes,
            avg_memory_bytes: self.throughput.avg_memory_bytes,
        }
    }

    // Private helper methods

    fn try_send_update(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update_time) >= self.update_interval {
            self.force_send_update();
        }
    }

    fn force_send_update(&mut self) {
        let update = self.create_progress_update(None);
        self.send_update(update);
        self.last_update_time = Instant::now();
    }

    fn create_progress_update(&self, message: Option<String>) -> ProgressUpdate {
        let elapsed = self.start_time.elapsed();

        // Calculate progress percentage
        let progress_percentage = if let Some(total) = self.total_steps {
            if total > 0 {
                (self.current_step as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        } else {
            // Use a heuristic based on processing time for unknown total
            let elapsed_seconds = elapsed.as_secs_f64();
            if elapsed_seconds < 1.0 {
                elapsed_seconds * 10.0 // Quick ramp-up
            } else {
                50.0 + (elapsed_seconds - 1.0).min(45.0) // Gradual increase, cap at 95%
            }
        };

        // Calculate processing rate
        let processing_rate = if elapsed.as_secs_f64() > 0.0 {
            self.entries_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        // Estimate time remaining
        let eta_seconds = if let Some(total) = self.total_steps {
            if self.current_step > 0 && processing_rate > 0.0 {
                let remaining_steps = total.saturating_sub(self.current_step);
                Some(remaining_steps as f64 / processing_rate)
            } else {
                None
            }
        } else {
            None
        };

        // Update throughput metrics
        let mut throughput = self.throughput.clone();
        throughput.entries_per_second = processing_rate;
        throughput.bytes_per_second = if elapsed.as_secs_f64() > 0.0 {
            self.bytes_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        ProgressUpdate {
            operation_id: self.operation_id.clone(),
            current_step: self.current_step,
            total_steps: self.total_steps,
            entries_processed: self.entries_processed,
            memory_usage: self.throughput.avg_memory_bytes,
            processing_rate,
            eta_seconds,
            progress_percentage: progress_percentage.min(100.0),
            phase: self.current_phase.clone(),
            message,
            elapsed_time: elapsed,
            throughput,
        }
    }

    fn send_update(&self, update: ProgressUpdate) {
        // Send to callbacks
        for callback in &self.callbacks {
            callback(update.clone());
        }

        // Send to broadcast channel if available
        if let Some(sender) = &self.broadcast_sender {
            let _ = sender.send(update);
        }
    }
}

/// Progress statistics summary
#[derive(Debug, Clone)]
pub struct ProgressStats {
    pub operation_id: String,
    pub entries_processed: usize,
    pub bytes_processed: usize,
    pub elapsed_time: Duration,
    pub entries_per_second: f64,
    pub current_phase: ProgressPhase,
    pub peak_memory_bytes: usize,
    pub avg_memory_bytes: usize,
}

/// Multi-operation progress tracker
pub struct ProgressTracker {
    operations: Arc<RwLock<std::collections::HashMap<String, ProgressReporter>>>,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new() -> Self {
        Self {
            operations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a new operation
    pub async fn register_operation(&self, operation_id: String) -> ProgressReporter {
        let reporter = ProgressReporter::new(operation_id.clone());
        let mut operations = self.operations.write().await;
        operations.insert(operation_id, reporter.clone());
        reporter
    }

    /// Get progress for an operation
    pub async fn get_progress(&self, operation_id: &str) -> Option<ProgressStats> {
        let operations = self.operations.read().await;
        operations
            .get(operation_id)
            .map(|reporter| reporter.get_stats())
    }

    /// Get progress for all operations
    pub async fn get_all_progress(&self) -> Vec<ProgressStats> {
        let operations = self.operations.read().await;
        operations
            .values()
            .map(|reporter| reporter.get_stats())
            .collect()
    }

    /// Remove completed operation
    pub async fn remove_operation(&self, operation_id: &str) {
        let mut operations = self.operations.write().await;
        operations.remove(operation_id);
    }

    /// Get operation count
    pub async fn operation_count(&self) -> usize {
        let operations = self.operations.read().await;
        operations.len()
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Console progress display
pub struct ConsoleProgressDisplay {
    last_message_len: usize,
}

impl ConsoleProgressDisplay {
    /// Create a new console progress display
    pub fn new() -> Self {
        Self {
            last_message_len: 0,
        }
    }

    /// Display progress update
    pub fn display(&mut self, update: &ProgressUpdate) {
        // Clear previous line
        if self.last_message_len > 0 {
            print!("\r{}", " ".repeat(self.last_message_len));
            print!("\r");
        }

        // Format progress message
        let progress_bar = self.create_progress_bar(update.progress_percentage);
        let rate_display = if update.processing_rate > 0.0 {
            format!(" ({:.1} entries/s)", update.processing_rate)
        } else {
            String::new()
        };

        let eta_display = if let Some(eta) = update.eta_seconds {
            format!(" ETA: {:.1}s", eta)
        } else {
            String::new()
        };

        let memory_display = if update.memory_usage > 0 {
            format!(" Mem: {}", format_bytes(update.memory_usage))
        } else {
            String::new()
        };

        let message = format!(
            "{} [{:>3.0}%] {} processed{}{}{} ({:?})",
            progress_bar,
            update.progress_percentage,
            update.entries_processed,
            rate_display,
            eta_display,
            memory_display,
            update.phase
        );

        print!("{}", message);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        self.last_message_len = message.len();

        // Print newline for completed or failed operations
        match update.phase {
            ProgressPhase::Completed | ProgressPhase::Failed(_) => {
                println!();
                self.last_message_len = 0;
            }
            _ => {}
        }
    }

    fn create_progress_bar(&self, percentage: f64) -> String {
        let width = 20;
        let filled = ((percentage / 100.0) * width as f64) as usize;
        let empty = width - filled;

        format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
    }
}

impl Default for ConsoleProgressDisplay {
    fn default() -> Self {
        Self::new()
    }
}

fn format_bytes(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_progress_reporter_creation() {
        let reporter = ProgressReporter::new("test_op".to_string());
        let stats = reporter.get_stats();

        assert_eq!(stats.operation_id, "test_op");
        assert_eq!(stats.entries_processed, 0);
        assert!(matches!(stats.current_phase, ProgressPhase::Initializing));
    }

    #[test]
    fn test_progress_update_calculation() {
        let mut reporter = ProgressReporter::new("test_op".to_string());
        reporter.set_total_steps(100);
        reporter.update_step(50);

        let update = reporter.create_progress_update(None);
        assert_eq!(update.progress_percentage, 50.0);
    }

    #[test]
    fn test_throughput_calculation() {
        let mut reporter = ProgressReporter::new("test_op".to_string());

        // Simulate some processing
        std::thread::sleep(Duration::from_millis(100));
        reporter.update_entries(1000, 50000);

        let stats = reporter.get_stats();
        assert!(stats.entries_per_second > 0.0);
    }

    #[test]
    fn test_memory_tracking() {
        let mut reporter = ProgressReporter::new("test_op".to_string());

        reporter.update_memory(1024);
        reporter.update_memory(2048);
        reporter.update_memory(1536);

        assert_eq!(reporter.throughput.peak_memory_bytes, 2048);
        assert!(reporter.throughput.avg_memory_bytes > 0);
    }

    #[test]
    fn test_phase_tracking() {
        let mut reporter = ProgressReporter::new("test_op".to_string());

        reporter.set_phase(ProgressPhase::Loading);
        std::thread::sleep(Duration::from_millis(10));
        reporter.set_phase(ProgressPhase::Processing);

        assert!(reporter.throughput.phase_times.contains_key("Initializing"));
    }

    #[tokio::test]
    async fn test_progress_callback() {
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = callback_count.clone();

        let callback: ProgressCallback = Arc::new(move |_update| {
            callback_count_clone.fetch_add(1, Ordering::Relaxed);
        });

        let mut reporter = ProgressReporter::new("test_op".to_string());
        reporter.add_callback(callback);
        reporter.set_update_interval(Duration::from_millis(1)); // Very frequent updates for testing

        reporter.update_entries(100, 1000);
        reporter.force_send_update();

        assert!(callback_count.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_broadcast_channel() {
        let (mut reporter, mut receiver) =
            ProgressReporter::with_broadcast("test_op".to_string(), 10);

        // Send an update
        reporter.update_entries(100, 1000);
        reporter.force_send_update();

        // Receive the update
        let update = receiver.recv().await.unwrap();
        assert_eq!(update.operation_id, "test_op");
        assert_eq!(update.entries_processed, 100);
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let tracker = ProgressTracker::new();

        let _reporter1 = tracker.register_operation("op1".to_string()).await;
        let _reporter2 = tracker.register_operation("op2".to_string()).await;

        assert_eq!(tracker.operation_count().await, 2);

        let all_progress = tracker.get_all_progress().await;
        assert_eq!(all_progress.len(), 2);

        tracker.remove_operation("op1").await;
        assert_eq!(tracker.operation_count().await, 1);
    }

    #[test]
    fn test_console_progress_display() {
        let mut display = ConsoleProgressDisplay::new();

        let update = ProgressUpdate {
            operation_id: "test".to_string(),
            current_step: 50,
            total_steps: Some(100),
            entries_processed: 5000,
            memory_usage: 1024 * 1024,
            processing_rate: 100.0,
            eta_seconds: Some(30.0),
            progress_percentage: 50.0,
            phase: ProgressPhase::Processing,
            message: None,
            elapsed_time: Duration::from_secs(10),
            throughput: ThroughputMetrics::default(),
        };

        // This should not panic
        display.display(&update);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1536 * 1024 * 1024), "1.5 GB");
    }

    #[test]
    fn test_progress_phases() {
        let phases = vec![
            ProgressPhase::Initializing,
            ProgressPhase::Loading,
            ProgressPhase::Processing,
            ProgressPhase::ProofGeneration,
            ProgressPhase::Buffering,
            ProgressPhase::Writing,
            ProgressPhase::Finalizing,
            ProgressPhase::Completed,
            ProgressPhase::Failed("error".to_string()),
        ];

        // Test serialization/deserialization
        for phase in phases {
            let serialized = serde_json::to_string(&phase).unwrap();
            let deserialized: ProgressPhase = serde_json::from_str(&serialized).unwrap();
            assert!(matches!(deserialized, _));
        }
    }

    #[test]
    fn test_throughput_metrics() {
        let mut metrics = ThroughputMetrics::default();

        assert_eq!(metrics.entries_per_second, 0.0);
        assert_eq!(metrics.bytes_per_second, 0.0);
        assert_eq!(metrics.peak_memory_bytes, 0);

        metrics.entries_per_second = 100.0;
        metrics.peak_memory_bytes = 1024;

        assert_eq!(metrics.entries_per_second, 100.0);
        assert_eq!(metrics.peak_memory_bytes, 1024);
    }
}

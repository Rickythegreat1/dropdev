use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

/// Reason a reconciliation scan was requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanReason {
    /// User/API requested a scan.
    Manual,
    /// Filesystem watcher produced a hint.
    WatcherHint,
    /// Periodic reconciliation timer requested a scan.
    Periodic,
}

/// Scan request queued for a registered project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Registered project ID.
    pub project_id: String,
    /// Why the scan was requested.
    pub reason: ScanReason,
    /// Whether this request came from an authoritative source.
    pub source_is_truth: bool,
}

impl ScanRequest {
    /// Creates a non-authoritative scan request.
    pub fn new(project_id: impl Into<String>, reason: ScanReason) -> Self {
        Self {
            project_id: project_id.into(),
            reason,
            source_is_truth: false,
        }
    }
}

/// Queue decision returned after enqueue attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanQueueDecision {
    /// Whether a request was queued.
    pub queued: bool,
    /// Whether this request was folded into a recent queued request.
    pub deduped: bool,
    /// Current queue length.
    pub queue_len: usize,
    /// Human-readable non-mutating summary.
    pub summary: String,
}

#[derive(Debug)]
struct QueueState {
    pending: VecDeque<ScanRequest>,
    last_enqueued: HashMap<String, Instant>,
}

/// Debounced in-memory queue for reconciliation scans.
#[derive(Debug, Clone)]
pub struct ScanQueue {
    debounce: Duration,
    state: Arc<Mutex<QueueState>>,
}

impl ScanQueue {
    /// Creates an empty scan queue.
    pub fn new(debounce: Duration) -> Self {
        Self {
            debounce,
            state: Arc::new(Mutex::new(QueueState {
                pending: VecDeque::new(),
                last_enqueued: HashMap::new(),
            })),
        }
    }

    /// Enqueues a scan request or de-duplicates it inside the debounce window.
    pub fn enqueue(&self, request: ScanRequest) -> ScanQueueDecision {
        let mut state = self.state.lock().expect("scan queue lock");
        let now = Instant::now();

        if let Some(previous) = state.last_enqueued.get(&request.project_id) {
            if now.duration_since(*previous) < self.debounce {
                return ScanQueueDecision {
                    queued: false,
                    deduped: true,
                    queue_len: state.pending.len(),
                    summary:
                        "Scan request de-duplicated inside debounce window; no files were mutated."
                            .to_string(),
                };
            }
        }

        state.last_enqueued.insert(request.project_id.clone(), now);
        state.pending.push_back(request);
        ScanQueueDecision {
            queued: true,
            deduped: false,
            queue_len: state.pending.len(),
            summary: "Reconciliation scan queued. Watcher events remain hints only.".to_string(),
        }
    }

    /// Pops the next queued scan request.
    pub fn pop_next(&self) -> Option<ScanRequest> {
        self.state
            .lock()
            .expect("scan queue lock")
            .pending
            .pop_front()
    }

    /// Current queue length.
    pub fn len(&self) -> usize {
        self.state.lock().expect("scan queue lock").pending.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn queue_debounces_duplicate_project_requests() {
        let queue = ScanQueue::new(Duration::from_secs(60));
        let first = queue.enqueue(ScanRequest::new("project:ready", ScanReason::Manual));
        let second = queue.enqueue(ScanRequest::new("project:ready", ScanReason::WatcherHint));

        assert!(first.queued);
        assert!(!first.deduped);
        assert!(!second.queued);
        assert!(second.deduped);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn queue_allows_after_debounce_window() {
        let queue = ScanQueue::new(Duration::from_millis(1));
        assert!(
            queue
                .enqueue(ScanRequest::new("project:ready", ScanReason::Manual))
                .queued
        );
        thread::sleep(Duration::from_millis(5));
        assert!(
            queue
                .enqueue(ScanRequest::new("project:ready", ScanReason::Manual))
                .queued
        );
        assert_eq!(queue.len(), 2);
    }
}

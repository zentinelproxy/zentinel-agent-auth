//! Background session cleanup task.
//!
//! Periodically evicts expired sessions and assertion records from the store.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

use super::store::SessionStore;

/// Default cleanup interval in seconds.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Spawn a background task that periodically cleans up expired sessions.
///
/// Returns a `JoinHandle` that can be used to abort the task.
pub fn spawn_cleanup_task(
    session_store: Arc<SessionStore>,
    cleanup_interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(cleanup_interval_secs));

        // Skip the first immediate tick
        ticker.tick().await;

        loop {
            ticker.tick().await;

            match session_store.evict_expired() {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            evicted = count,
                            "Session cleanup completed"
                        );
                    } else {
                        debug!("Session cleanup: no expired sessions");
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Session cleanup failed"
                    );
                }
            }

            // Log session count periodically for observability
            match session_store.session_count() {
                Ok(count) => {
                    debug!(active_sessions = count, "Session store status");
                }
                Err(e) => {
                    debug!(error = %e, "Failed to get session count");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::types::Session;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cleanup_task_runs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.redb");
        let store = Arc::new(SessionStore::open(path, 1).unwrap());

        // Create a valid session (shouldn't be cleaned up)
        let _ = store.create(Session::new(
            "test@example.com".to_string(),
            "valid-assertion".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        ));

        assert_eq!(store.session_count().unwrap(), 1, "Should have 1 session");

        // Spawn cleanup with very short interval for testing
        let handle = spawn_cleanup_task(Arc::clone(&store), 1);

        // Wait for at least one cleanup cycle
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Abort the task
        handle.abort();

        // Valid session should still exist (cleanup runs without error)
        let count = store.session_count().unwrap();
        assert_eq!(count, 1, "Valid session should not be cleaned up");
    }
}

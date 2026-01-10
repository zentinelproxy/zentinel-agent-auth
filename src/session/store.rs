//! Session store backed by redb embedded database.
//!
//! Provides persistent storage for SAML sessions with:
//! - In-memory cache for hot sessions
//! - Replay prevention via assertion ID tracking
//! - TTL-based expiry

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{debug, warn};

use super::types::{Session, SessionId};

/// redb table for sessions (key: session_id hex, value: MessagePack bytes).
const SESSIONS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("saml_sessions");

/// redb table for assertion ID tracking (key: assertion_id, value: expiry timestamp).
const ASSERTIONS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("saml_assertions");

/// Session store with in-memory cache and persistent storage.
pub struct SessionStore {
    /// redb database handle.
    db: Database,

    /// In-memory cache for frequently accessed sessions.
    cache: RwLock<HashMap<SessionId, Session>>,

    /// Default session TTL in seconds.
    default_ttl_secs: u64,

    /// Maximum number of sessions to keep in cache.
    max_cache_size: usize,
}

impl SessionStore {
    /// Open or create a session store at the given path.
    pub fn open(path: PathBuf, default_ttl_secs: u64) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        }

        let db = Database::create(&path)
            .with_context(|| format!("Failed to open session database: {:?}", path))?;

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(SESSIONS_TABLE)?;
            let _ = write_txn.open_table(ASSERTIONS_TABLE)?;
        }
        write_txn.commit()?;

        // Load active sessions into cache
        let cache = Self::load_active_sessions(&db)?;
        let cache_count = cache.len();

        debug!(sessions = cache_count, "Loaded active sessions into cache");

        Ok(Self {
            db,
            cache: RwLock::new(cache),
            default_ttl_secs,
            max_cache_size: 10000,
        })
    }

    /// Get default TTL in seconds.
    pub fn default_ttl_secs(&self) -> u64 {
        self.default_ttl_secs
    }

    /// Create a new session and store it.
    pub fn create(&self, session: Session) -> Result<SessionId> {
        let id = session.id;

        // Check for assertion replay
        if self.is_assertion_used(&session.assertion_id)? {
            anyhow::bail!("SAML assertion replay detected: {}", session.assertion_id);
        }

        // Mark assertion as used
        self.mark_assertion_used(&session.assertion_id, session.expires_at)?;

        // Persist to database
        self.persist(&session)?;

        // Add to cache
        if let Ok(mut cache) = self.cache.write() {
            // Evict from cache if too large
            if cache.len() >= self.max_cache_size {
                self.evict_cache_lru(&mut cache);
            }
            cache.insert(id, session);
        }

        Ok(id)
    }

    /// Get session by ID, updating last_accessed time.
    pub fn get(&self, id: SessionId) -> Result<Option<Session>> {
        // Check cache first
        if let Ok(mut cache) = self.cache.write() {
            if let Some(session) = cache.get_mut(&id) {
                if session.is_expired() {
                    cache.remove(&id);
                    // Don't delete from DB here, let cleanup handle it
                    return Ok(None);
                }
                session.touch();
                // Persist updated last_accessed
                let _ = self.persist(session);
                return Ok(Some(session.clone()));
            }
        }

        // Check database
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SESSIONS_TABLE)?;

        let key = id.to_hex();
        match table.get(key.as_str())? {
            Some(value) => {
                let mut session: Session = rmp_serde::from_slice(value.value())
                    .context("Failed to deserialize session")?;

                if session.is_expired() {
                    return Ok(None);
                }

                session.touch();

                // Add to cache
                if let Ok(mut cache) = self.cache.write() {
                    cache.insert(id, session.clone());
                }

                // Persist updated last_accessed (drop read_txn first)
                drop(read_txn);
                let _ = self.persist(&session);

                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Delete a session by ID.
    pub fn delete(&self, id: SessionId) -> Result<bool> {
        // Remove from cache
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(&id);
        }

        // Remove from database
        let write_txn = self.db.begin_write()?;
        let removed = {
            let mut table = write_txn.open_table(SESSIONS_TABLE)?;
            let key = id.to_hex();
            let result = table.remove(key.as_str())?;
            result.is_some()
        };
        write_txn.commit()?;

        Ok(removed)
    }

    /// Delete all sessions for a user (for logout).
    pub fn delete_by_user(&self, user_id: &str) -> Result<usize> {
        let mut deleted = 0;

        // Find all sessions for user
        let sessions_to_delete: Vec<SessionId> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SESSIONS_TABLE)?;

            let mut ids = Vec::new();
            for entry in table.iter()? {
                let (_, value) = entry?;
                let session: Session = rmp_serde::from_slice(value.value())?;
                if session.user_id == user_id {
                    ids.push(session.id);
                }
            }
            ids
        };

        // Delete each session
        for id in sessions_to_delete {
            if self.delete(id)? {
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    /// Check if an assertion ID has been used (replay prevention).
    pub fn is_assertion_used(&self, assertion_id: &str) -> Result<bool> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ASSERTIONS_TABLE)?;
        Ok(table.get(assertion_id)?.is_some())
    }

    /// Mark an assertion ID as used.
    fn mark_assertion_used(&self, assertion_id: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let data = rmp_serde::to_vec(&expires_at)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ASSERTIONS_TABLE)?;
            table.insert(assertion_id, data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Evict all expired sessions and assertion records.
    /// Returns the number of sessions evicted.
    pub fn evict_expired(&self) -> Result<usize> {
        let now = Utc::now();
        let mut evicted = 0;

        // Evict from cache
        if let Ok(mut cache) = self.cache.write() {
            let before = cache.len();
            cache.retain(|_, session| !session.is_expired());
            evicted = before - cache.len();
        }

        // Collect expired session IDs from database
        let expired_sessions: Vec<String> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SESSIONS_TABLE)?;

            let mut ids = Vec::new();
            for entry in table.iter()? {
                let (key, value) = entry?;
                match rmp_serde::from_slice::<Session>(value.value()) {
                    Ok(session) if session.is_expired() => {
                        ids.push(key.value().to_string());
                    }
                    Err(e) => {
                        warn!(key = key.value(), error = %e, "Failed to deserialize session, marking for deletion");
                        ids.push(key.value().to_string());
                    }
                    _ => {}
                }
            }
            ids
        };

        // Delete expired sessions
        for id in &expired_sessions {
            let write_txn = self.db.begin_write()?;
            let removed = {
                let mut table = write_txn.open_table(SESSIONS_TABLE)?;
                let result = table.remove(id.as_str())?;
                result.is_some()
            };
            write_txn.commit()?;
            if removed && evicted == 0 {
                evicted += 1;
            }
        }

        // Collect expired assertion records
        let expired_assertions: Vec<String> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(ASSERTIONS_TABLE)?;

            let mut ids = Vec::new();
            for entry in table.iter()? {
                let (key, value) = entry?;
                match rmp_serde::from_slice::<DateTime<Utc>>(value.value()) {
                    Ok(expires_at) if now > expires_at => {
                        ids.push(key.value().to_string());
                    }
                    Err(_) => {
                        ids.push(key.value().to_string());
                    }
                    _ => {}
                }
            }
            ids
        };

        // Delete expired assertions
        for id in expired_assertions {
            let write_txn = self.db.begin_write()?;
            {
                let mut table = write_txn.open_table(ASSERTIONS_TABLE)?;
                table.remove(id.as_str())?;
            }
            write_txn.commit()?;
        }

        Ok(evicted)
    }

    /// Get session count (for metrics).
    pub fn session_count(&self) -> Result<usize> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SESSIONS_TABLE)?;
        Ok(table.len()? as usize)
    }

    /// Persist a session to the database.
    fn persist(&self, session: &Session) -> Result<()> {
        let data = rmp_serde::to_vec(session).context("Failed to serialize session")?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SESSIONS_TABLE)?;
            table.insert(session.id.to_hex().as_str(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Load all non-expired sessions into cache.
    fn load_active_sessions(db: &Database) -> Result<HashMap<SessionId, Session>> {
        let mut sessions = HashMap::new();
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(SESSIONS_TABLE)?;

        for entry in table.iter()? {
            let (_, value) = entry?;
            match rmp_serde::from_slice::<Session>(value.value()) {
                Ok(session) if !session.is_expired() => {
                    sessions.insert(session.id, session);
                }
                _ => {}
            }
        }

        Ok(sessions)
    }

    /// Evict least recently accessed sessions from cache.
    fn evict_cache_lru(&self, cache: &mut HashMap<SessionId, Session>) {
        // Simple LRU: find oldest last_accessed and remove
        if let Some(oldest_id) = cache
            .iter()
            .min_by_key(|(_, s)| s.last_accessed)
            .map(|(id, _)| *id)
        {
            cache.remove(&oldest_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_store() -> (SessionStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.redb");
        let store = SessionStore::open(path, 3600).unwrap();
        (store, dir)
    }

    #[test]
    fn test_session_create_and_get() {
        let (store, _dir) = test_store();

        let session = Session::new(
            "user@example.com".to_string(),
            "assertion-123".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );
        let id = session.id;

        store.create(session).unwrap();

        let retrieved = store.get(id).unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user@example.com");
        assert_eq!(retrieved.assertion_id, "assertion-123");
    }

    #[test]
    fn test_session_expiry() {
        let (store, _dir) = test_store();

        let mut session = Session::new(
            "user@example.com".to_string(),
            "assertion-456".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );
        // Manually expire
        session.expires_at = Utc::now() - chrono::Duration::seconds(10);
        let id = session.id;

        store.create(session).unwrap();

        // Should return None for expired session
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn test_assertion_replay_prevention() {
        let (store, _dir) = test_store();

        let session1 = Session::new(
            "user@example.com".to_string(),
            "unique-assertion".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );
        store.create(session1).unwrap();

        // Try to create another session with same assertion ID
        let session2 = Session::new(
            "other@example.com".to_string(),
            "unique-assertion".to_string(), // Same assertion ID
            "https://idp.example.com".to_string(),
            3600,
        );
        let result = store.create(session2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn test_session_delete() {
        let (store, _dir) = test_store();

        let session = Session::new(
            "user@example.com".to_string(),
            "assertion-789".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );
        let id = session.id;

        store.create(session).unwrap();
        assert!(store.get(id).unwrap().is_some());

        assert!(store.delete(id).unwrap());
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn test_evict_expired() {
        let (store, _dir) = test_store();

        // Create an expired session
        let mut session = Session::new(
            "user@example.com".to_string(),
            "assertion-expired".to_string(),
            "https://idp.example.com".to_string(),
            3600,
        );
        session.expires_at = Utc::now() - chrono::Duration::seconds(10);

        // Bypass replay check by creating normally first, then we'll test eviction
        let _ = store.persist(&session);

        let evicted = store.evict_expired().unwrap();
        assert!(evicted >= 1);
    }
}

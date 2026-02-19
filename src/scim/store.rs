//! SCIM user store backed by redb embedded database.
//!
//! Provides persistent storage for SCIM-provisioned users with:
//! - In-memory cache for fast lookups
//! - Secondary indexes for externalId and userName
//! - Transactional consistency across all three tables

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::{debug, warn};

use super::types::ScimUser;

/// Primary user table: UUID -> MessagePack<ScimUser>.
const SCIM_USERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("scim_users");
/// Secondary index: externalId -> UUID.
const SCIM_EXT_INDEX: TableDefinition<&str, &str> = TableDefinition::new("scim_ext_index");
/// Secondary index: userName -> UUID.
const SCIM_USERNAME_INDEX: TableDefinition<&str, &str> = TableDefinition::new("scim_username_index");

/// Loaded cache tuple: (users, ext_id_index, username_index).
type LoadedCaches = (HashMap<String, ScimUser>, HashMap<String, String>, HashMap<String, String>);

/// SCIM user store with in-memory caches and persistent storage.
pub struct ScimUserStore {
    db: Database,
    /// Primary cache: UUID -> ScimUser.
    user_cache: RwLock<HashMap<String, ScimUser>>,
    /// Index cache: externalId -> UUID.
    ext_id_cache: RwLock<HashMap<String, String>>,
    /// Index cache: userName -> UUID.
    username_cache: RwLock<HashMap<String, String>>,
}

impl ScimUserStore {
    /// Open or create a SCIM user store at the given path.
    pub fn open(path: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        }

        let db = Database::create(&path)
            .with_context(|| format!("Failed to open SCIM user database: {:?}", path))?;

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(SCIM_USERS_TABLE)?;
            let _ = write_txn.open_table(SCIM_EXT_INDEX)?;
            let _ = write_txn.open_table(SCIM_USERNAME_INDEX)?;
        }
        write_txn.commit()?;

        // Load all users into cache
        let (user_cache, ext_id_cache, username_cache) = Self::load_all(&db)?;
        let user_count = user_cache.len();

        debug!(users = user_count, "Loaded SCIM users into cache");

        Ok(Self {
            db,
            user_cache: RwLock::new(user_cache),
            ext_id_cache: RwLock::new(ext_id_cache),
            username_cache: RwLock::new(username_cache),
        })
    }

    /// Create a new SCIM user. Returns 409 error on duplicate userName.
    pub fn create(&self, user: ScimUser) -> Result<ScimUser> {
        // Check for duplicate userName
        if let Ok(cache) = self.username_cache.read() {
            if cache.contains_key(&user.user_name) {
                anyhow::bail!("userName '{}' already exists", user.user_name);
            }
        }

        // Persist to database with indexes in a single transaction
        let data = rmp_serde::to_vec_named(&user).context("Failed to serialize SCIM user")?;
        let write_txn = self.db.begin_write()?;
        {
            let mut users_table = write_txn.open_table(SCIM_USERS_TABLE)?;
            let mut username_index = write_txn.open_table(SCIM_USERNAME_INDEX)?;
            let mut ext_index = write_txn.open_table(SCIM_EXT_INDEX)?;

            users_table.insert(user.id.as_str(), data.as_slice())?;
            username_index.insert(user.user_name.as_str(), user.id.as_str())?;
            if let Some(ref ext_id) = user.external_id {
                ext_index.insert(ext_id.as_str(), user.id.as_str())?;
            }
        }
        write_txn.commit()?;

        // Update caches
        if let Ok(mut cache) = self.user_cache.write() {
            cache.insert(user.id.clone(), user.clone());
        }
        if let Ok(mut cache) = self.username_cache.write() {
            cache.insert(user.user_name.clone(), user.id.clone());
        }
        if let Some(ref ext_id) = user.external_id {
            if let Ok(mut cache) = self.ext_id_cache.write() {
                cache.insert(ext_id.clone(), user.id.clone());
            }
        }

        Ok(user)
    }

    /// Get a SCIM user by UUID.
    pub fn get(&self, id: &str) -> Result<Option<ScimUser>> {
        // Check cache first
        if let Ok(cache) = self.user_cache.read() {
            if let Some(user) = cache.get(id) {
                return Ok(Some(user.clone()));
            }
        }

        // Fall back to database
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SCIM_USERS_TABLE)?;
        match table.get(id)? {
            Some(value) => {
                let user: ScimUser = rmp_serde::from_slice(value.value())
                    .context("Failed to deserialize SCIM user")?;

                // Populate cache
                if let Ok(mut cache) = self.user_cache.write() {
                    cache.insert(user.id.clone(), user.clone());
                }

                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    /// Get a SCIM user by externalId.
    pub fn get_by_external_id(&self, ext_id: &str) -> Result<Option<ScimUser>> {
        // Look up UUID from index cache
        let uuid = if let Ok(cache) = self.ext_id_cache.read() {
            cache.get(ext_id).cloned()
        } else {
            None
        };

        if let Some(uuid) = uuid {
            return self.get(&uuid);
        }

        // Fall back to database index
        let uuid = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SCIM_EXT_INDEX)?;
            table.get(ext_id)?.map(|value| value.value().to_string())
        };

        match uuid {
            Some(uuid) => self.get(&uuid),
            None => Ok(None),
        }
    }

    /// Get a SCIM user by userName.
    pub fn get_by_username(&self, username: &str) -> Result<Option<ScimUser>> {
        // Look up UUID from index cache
        let uuid = if let Ok(cache) = self.username_cache.read() {
            cache.get(username).cloned()
        } else {
            None
        };

        if let Some(uuid) = uuid {
            return self.get(&uuid);
        }

        // Fall back to database index
        let uuid = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SCIM_USERNAME_INDEX)?;
            table.get(username)?.map(|value| value.value().to_string())
        };

        match uuid {
            Some(uuid) => self.get(&uuid),
            None => Ok(None),
        }
    }

    /// List SCIM users with pagination.
    /// `start_index` is 1-based per SCIM spec.
    /// Returns (users, total_count).
    pub fn list(&self, start_index: usize, count: usize) -> Result<(Vec<ScimUser>, usize)> {
        if let Ok(cache) = self.user_cache.read() {
            let total = cache.len();
            let offset = if start_index > 0 { start_index - 1 } else { 0 };
            let mut users: Vec<ScimUser> = cache.values().cloned().collect();
            // Sort by userName for consistent ordering
            users.sort_by(|a, b| a.user_name.cmp(&b.user_name));
            let page: Vec<ScimUser> = users.into_iter().skip(offset).take(count).collect();
            return Ok((page, total));
        }

        // Fall back to database
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SCIM_USERS_TABLE)?;
        let total = table.len()? as usize;

        let offset = if start_index > 0 { start_index - 1 } else { 0 };
        let mut users = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            match rmp_serde::from_slice::<ScimUser>(value.value()) {
                Ok(user) => users.push(user),
                Err(e) => {
                    warn!(error = %e, "Failed to deserialize SCIM user, skipping");
                }
            }
        }
        users.sort_by(|a, b| a.user_name.cmp(&b.user_name));
        let page: Vec<ScimUser> = users.into_iter().skip(offset).take(count).collect();

        Ok((page, total))
    }

    /// Replace a SCIM user (full PUT). Updates indexes atomically.
    pub fn replace(&self, id: &str, mut user: ScimUser) -> Result<ScimUser> {
        // Get old user to clean up old indexes
        let old_user = self.get(id)?
            .ok_or_else(|| anyhow::anyhow!("User '{}' not found", id))?;

        // Check for userName conflict (if changed)
        if old_user.user_name != user.user_name {
            if let Ok(cache) = self.username_cache.read() {
                if cache.contains_key(&user.user_name) {
                    anyhow::bail!("userName '{}' already exists", user.user_name);
                }
            }
        }

        // Preserve server-assigned fields
        user.id = id.to_string();
        user.meta.last_modified = chrono::Utc::now();

        let data = rmp_serde::to_vec_named(&user).context("Failed to serialize SCIM user")?;

        // Update database in a single transaction
        let write_txn = self.db.begin_write()?;
        {
            let mut users_table = write_txn.open_table(SCIM_USERS_TABLE)?;
            let mut username_index = write_txn.open_table(SCIM_USERNAME_INDEX)?;
            let mut ext_index = write_txn.open_table(SCIM_EXT_INDEX)?;

            // Remove old indexes
            username_index.remove(old_user.user_name.as_str())?;
            if let Some(ref old_ext_id) = old_user.external_id {
                ext_index.remove(old_ext_id.as_str())?;
            }

            // Insert new data + indexes
            users_table.insert(id, data.as_slice())?;
            username_index.insert(user.user_name.as_str(), id)?;
            if let Some(ref ext_id) = user.external_id {
                ext_index.insert(ext_id.as_str(), id)?;
            }
        }
        write_txn.commit()?;

        // Update caches
        if let Ok(mut cache) = self.username_cache.write() {
            cache.remove(&old_user.user_name);
            cache.insert(user.user_name.clone(), id.to_string());
        }
        if let Ok(mut cache) = self.ext_id_cache.write() {
            if let Some(ref old_ext_id) = old_user.external_id {
                cache.remove(old_ext_id);
            }
            if let Some(ref ext_id) = user.external_id {
                cache.insert(ext_id.clone(), id.to_string());
            }
        }
        if let Ok(mut cache) = self.user_cache.write() {
            cache.insert(id.to_string(), user.clone());
        }

        Ok(user)
    }

    /// Delete a SCIM user (sets active=false per SCIM convention).
    pub fn delete(&self, id: &str) -> Result<bool> {
        let mut user = match self.get(id)? {
            Some(u) => u,
            None => return Ok(false),
        };

        user.active = false;
        user.meta.last_modified = chrono::Utc::now();

        let data = rmp_serde::to_vec_named(&user).context("Failed to serialize SCIM user")?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SCIM_USERS_TABLE)?;
            table.insert(id, data.as_slice())?;
        }
        write_txn.commit()?;

        // Update cache
        if let Ok(mut cache) = self.user_cache.write() {
            cache.insert(id.to_string(), user);
        }

        Ok(true)
    }

    /// Get total user count.
    pub fn count(&self) -> Result<usize> {
        if let Ok(cache) = self.user_cache.read() {
            return Ok(cache.len());
        }
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SCIM_USERS_TABLE)?;
        Ok(table.len()? as usize)
    }

    /// Check if a user is active by externalId (for OIDC enforcement).
    pub fn is_user_active_by_external_id(&self, ext_id: &str) -> Result<Option<bool>> {
        match self.get_by_external_id(ext_id)? {
            Some(user) => Ok(Some(user.active)),
            None => Ok(None),
        }
    }

    /// Load all users and build index caches from database.
    fn load_all(db: &Database) -> Result<LoadedCaches> {
        let mut users = HashMap::new();
        let mut ext_ids = HashMap::new();
        let mut usernames = HashMap::new();

        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(SCIM_USERS_TABLE)?;

        for entry in table.iter()? {
            let (_, value) = entry?;
            match rmp_serde::from_slice::<ScimUser>(value.value()) {
                Ok(user) => {
                    usernames.insert(user.user_name.clone(), user.id.clone());
                    if let Some(ref ext_id) = user.external_id {
                        ext_ids.insert(ext_id.clone(), user.id.clone());
                    }
                    users.insert(user.id.clone(), user);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to deserialize SCIM user during load, skipping");
                }
            }
        }

        Ok((users, ext_ids, usernames))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_store() -> (ScimUserStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("scim_users.redb");
        let store = ScimUserStore::open(path).unwrap();
        (store, dir)
    }

    #[test]
    fn test_create_and_get() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("jdoe".to_string(), Some("ext-123".to_string()), "/scim/v2");
        let id = user.id.clone();

        let created = store.create(user).unwrap();
        assert_eq!(created.user_name, "jdoe");

        let retrieved = store.get(&id).unwrap().unwrap();
        assert_eq!(retrieved.user_name, "jdoe");
        assert_eq!(retrieved.external_id, Some("ext-123".to_string()));
    }

    #[test]
    fn test_get_by_external_id() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("jdoe".to_string(), Some("ext-456".to_string()), "/scim/v2");
        store.create(user).unwrap();

        let found = store.get_by_external_id("ext-456").unwrap().unwrap();
        assert_eq!(found.user_name, "jdoe");

        assert!(store.get_by_external_id("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_get_by_username() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("alice".to_string(), None, "/scim/v2");
        store.create(user).unwrap();

        let found = store.get_by_username("alice").unwrap().unwrap();
        assert_eq!(found.user_name, "alice");

        assert!(store.get_by_username("nobody").unwrap().is_none());
    }

    #[test]
    fn test_duplicate_username_rejected() {
        let (store, _dir) = test_store();
        let user1 = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        store.create(user1).unwrap();

        let user2 = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        let result = store.create(user2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_replace() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("jdoe".to_string(), Some("ext-1".to_string()), "/scim/v2");
        let id = user.id.clone();
        store.create(user).unwrap();

        let mut updated = store.get(&id).unwrap().unwrap();
        updated.user_name = "john.doe".to_string();
        updated.external_id = Some("ext-2".to_string());
        updated.display_name = Some("John Doe".to_string());

        let result = store.replace(&id, updated).unwrap();
        assert_eq!(result.user_name, "john.doe");
        assert_eq!(result.display_name, Some("John Doe".to_string()));

        // Old indexes cleaned up
        assert!(store.get_by_username("jdoe").unwrap().is_none());
        assert!(store.get_by_external_id("ext-1").unwrap().is_none());
        // New indexes work
        assert!(store.get_by_username("john.doe").unwrap().is_some());
        assert!(store.get_by_external_id("ext-2").unwrap().is_some());
    }

    #[test]
    fn test_delete_deactivates() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("jdoe".to_string(), None, "/scim/v2");
        let id = user.id.clone();
        store.create(user).unwrap();

        assert!(store.delete(&id).unwrap());

        let deleted = store.get(&id).unwrap().unwrap();
        assert!(!deleted.active);
    }

    #[test]
    fn test_delete_nonexistent() {
        let (store, _dir) = test_store();
        assert!(!store.delete("nonexistent").unwrap());
    }

    #[test]
    fn test_list_pagination() {
        let (store, _dir) = test_store();
        for i in 0..5 {
            let user = ScimUser::new(format!("user{}", i), None, "/scim/v2");
            store.create(user).unwrap();
        }

        let (page, total) = store.list(1, 2).unwrap();
        assert_eq!(total, 5);
        assert_eq!(page.len(), 2);

        let (page, total) = store.list(3, 2).unwrap();
        assert_eq!(total, 5);
        assert_eq!(page.len(), 2);

        let (page, total) = store.list(5, 10).unwrap();
        assert_eq!(total, 5);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn test_count() {
        let (store, _dir) = test_store();
        assert_eq!(store.count().unwrap(), 0);

        store.create(ScimUser::new("a".to_string(), None, "/scim/v2")).unwrap();
        store.create(ScimUser::new("b".to_string(), None, "/scim/v2")).unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_index_consistency_on_replace() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("alice".to_string(), Some("ext-a".to_string()), "/scim/v2");
        let id = user.id.clone();
        store.create(user).unwrap();

        // Replace with different userName and externalId
        let mut updated = store.get(&id).unwrap().unwrap();
        updated.user_name = "alice2".to_string();
        updated.external_id = Some("ext-b".to_string());
        store.replace(&id, updated).unwrap();

        // Verify old indexes are gone and new ones work
        assert!(store.get_by_username("alice").unwrap().is_none());
        assert!(store.get_by_external_id("ext-a").unwrap().is_none());
        assert_eq!(store.get_by_username("alice2").unwrap().unwrap().id, id);
        assert_eq!(store.get_by_external_id("ext-b").unwrap().unwrap().id, id);
    }

    #[test]
    fn test_persistence_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("scim_users.redb");

        let id = {
            let store = ScimUserStore::open(path.clone()).unwrap();
            let user = ScimUser::new("persistent".to_string(), Some("ext-p".to_string()), "/scim/v2");
            let id = user.id.clone();
            store.create(user).unwrap();
            id
        };

        // Reopen store
        let store = ScimUserStore::open(path).unwrap();
        let user = store.get(&id).unwrap().unwrap();
        assert_eq!(user.user_name, "persistent");
        assert!(store.get_by_username("persistent").unwrap().is_some());
        assert!(store.get_by_external_id("ext-p").unwrap().is_some());
    }

    #[test]
    fn test_is_user_active_by_external_id() {
        let (store, _dir) = test_store();
        let user = ScimUser::new("jdoe".to_string(), Some("oidc-sub".to_string()), "/scim/v2");
        let id = user.id.clone();
        store.create(user).unwrap();

        assert_eq!(store.is_user_active_by_external_id("oidc-sub").unwrap(), Some(true));

        store.delete(&id).unwrap();
        assert_eq!(store.is_user_active_by_external_id("oidc-sub").unwrap(), Some(false));

        assert_eq!(store.is_user_active_by_external_id("unknown").unwrap(), None);
    }
}

// scrt4/src/encrypted_inventory.rs
//! Encrypted-folder inventory (F027 list-encrypted, F028 cleanup-encrypted).
//!
//! Tracks the `.scrt4` archives produced by `scrt4 encrypt-folder` so the
//! user can later answer:
//!
//!   - "What did I encrypt and where did I put it?" (`list-encrypted`)
//!   - "Which archives have been moved/deleted on disk since registering?"
//!     (`cleanup-encrypted`)
//!
//! This is Core (crypto bookkeeping), not a module. The reclassification
//! from encrypt-folder module stubs to Core was made on 2026-04-13 in the
//! architecture-branch work — see docs/ARCHITECTURE-V0.2.md.
//!
//! ## Storage
//!
//! `~/.scrt4/encrypted-inventory.json`
//!
//! ## Concurrency
//!
//! Load-modify-save pattern under the assumption that only one daemon
//! writes at a time (the socket is per-user and single-connection
//! serialised). No cross-process locking.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    /// Stable id (hash of path + created_at) — used for unregister.
    pub id: String,
    /// Absolute path to the .scrt4 archive.
    pub path: String,
    /// The folder name that was encrypted (from SCRT4ENC header).
    pub folder_name: String,
    /// How many files were in the source folder (informational).
    pub file_count: u32,
    /// Size of the archive in bytes at the time of registration.
    pub archive_size: u64,
    /// Unix ms when the archive was registered.
    pub created_at: u64,
    /// Unix ms when the archive was last successfully decrypted (if ever).
    pub last_decrypted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InventoryStore {
    pub version: u32,
    pub entries: Vec<EncryptedEntry>,
}

impl InventoryStore {
    fn empty() -> Self {
        InventoryStore { version: 1, entries: Vec::new() }
    }
}

// ── Path helpers ───────────────────────────────────────────────────

/// Returns the path to the encrypted-folder inventory file
/// (`~/.scrt4/encrypted-inventory.json`).
pub fn inventory_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".scrt4").join("encrypted-inventory.json")
}

// ── Load / save ────────────────────────────────────────────────────

pub fn load_inventory() -> InventoryStore {
    load_inventory_from(&inventory_path())
}

fn load_inventory_from(path: &std::path::Path) -> InventoryStore {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<InventoryStore>(&content) {
            Ok(store) => store,
            Err(e) => {
                tracing::warn!("Failed to parse encrypted inventory at {:?}: {}", path, e);
                InventoryStore::empty()
            }
        },
        Err(_) => InventoryStore::empty(),
    }
}

pub fn save_inventory(store: &InventoryStore) -> Result<(), String> {
    save_inventory_to(store, &inventory_path())
}

fn save_inventory_to(store: &InventoryStore, path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config dir {:?}: {}", parent, e))?;
    }
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| format!("Failed to serialize inventory: {}", e))?;
    std::fs::write(path, json)
        .map_err(|e| format!("Failed to write inventory {:?}: {}", path, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ── Operations ─────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn make_entry_id(path: &str, created_at: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    hasher.update(created_at.to_le_bytes());
    format!("{:x}", hasher.finalize())[..24].to_string()
}

/// Register a newly-created encrypted archive.
///
/// Deduplicates on the absolute path — if an entry for `path` already
/// exists, its archive_size/file_count/created_at are updated in place
/// (the user re-encrypted the same folder to the same destination).
pub fn register(
    path: &str,
    folder_name: &str,
    file_count: u32,
    archive_size: u64,
) -> Result<EncryptedEntry, String> {
    register_at(&inventory_path(), path, folder_name, file_count, archive_size)
}

fn register_at(
    store_path: &std::path::Path,
    path: &str,
    folder_name: &str,
    file_count: u32,
    archive_size: u64,
) -> Result<EncryptedEntry, String> {
    let mut store = load_inventory_from(store_path);
    let created_at = now_ms();

    if let Some(existing) = store.entries.iter_mut().find(|e| e.path == path) {
        existing.folder_name = folder_name.to_string();
        existing.file_count = file_count;
        existing.archive_size = archive_size;
        existing.created_at = created_at;
        existing.last_decrypted_at = None;
        let entry = existing.clone();
        save_inventory_to(&store, store_path)?;
        return Ok(entry);
    }

    let entry = EncryptedEntry {
        id: make_entry_id(path, created_at),
        path: path.to_string(),
        folder_name: folder_name.to_string(),
        file_count,
        archive_size,
        created_at,
        last_decrypted_at: None,
    };
    store.entries.push(entry.clone());
    save_inventory_to(&store, store_path)?;
    Ok(entry)
}

/// Mark an existing entry as freshly decrypted.
pub fn mark_decrypted(path: &str) -> Result<(), String> {
    mark_decrypted_at(&inventory_path(), path)
}

fn mark_decrypted_at(store_path: &std::path::Path, path: &str) -> Result<(), String> {
    let mut store = load_inventory_from(store_path);
    let mut found = false;
    for entry in store.entries.iter_mut() {
        if entry.path == path {
            entry.last_decrypted_at = Some(now_ms());
            found = true;
            break;
        }
    }
    if !found {
        return Ok(()); // silent no-op — decrypt of an un-registered archive is fine
    }
    save_inventory_to(&store, store_path)
}

/// Remove an entry by ID. Returns true if an entry was removed.
pub fn unregister(id: &str) -> Result<bool, String> {
    unregister_at(&inventory_path(), id)
}

fn unregister_at(store_path: &std::path::Path, id: &str) -> Result<bool, String> {
    let mut store = load_inventory_from(store_path);
    let before = store.entries.len();
    store.entries.retain(|e| e.id != id);
    let removed = store.entries.len() < before;
    if removed {
        save_inventory_to(&store, store_path)?;
    }
    Ok(removed)
}

/// Return the inventory with a per-entry "exists on disk" flag.
pub fn list_with_existence() -> Vec<(EncryptedEntry, bool)> {
    list_with_existence_at(&inventory_path())
}

fn list_with_existence_at(store_path: &std::path::Path) -> Vec<(EncryptedEntry, bool)> {
    let store = load_inventory_from(store_path);
    store
        .entries
        .into_iter()
        .map(|e| {
            let exists = std::path::Path::new(&e.path).is_file();
            (e, exists)
        })
        .collect()
}

/// Summary of a cleanup pass: how many entries still point at a file
/// that exists, how many don't, and how many were removed.
#[derive(Debug, Clone, Serialize)]
pub struct CleanupSummary {
    pub present_count: usize,
    pub missing_count: usize,
    pub removed_count: usize,
    pub missing_paths: Vec<String>,
}

/// Run a cleanup pass. If `remove_missing` is true, entries pointing
/// at a path that no longer exists on disk are removed from the
/// inventory. Either way, the summary tells the caller what it found.
pub fn cleanup(remove_missing: bool) -> Result<CleanupSummary, String> {
    cleanup_at(&inventory_path(), remove_missing)
}

fn cleanup_at(store_path: &std::path::Path, remove_missing: bool) -> Result<CleanupSummary, String> {
    let mut store = load_inventory_from(store_path);
    let mut present = 0usize;
    let mut missing = 0usize;
    let mut missing_paths: Vec<String> = Vec::new();

    for entry in store.entries.iter() {
        if std::path::Path::new(&entry.path).is_file() {
            present += 1;
        } else {
            missing += 1;
            missing_paths.push(entry.path.clone());
        }
    }

    let mut removed = 0usize;
    if remove_missing && missing > 0 {
        let before = store.entries.len();
        store
            .entries
            .retain(|e| std::path::Path::new(&e.path).is_file());
        removed = before - store.entries.len();
        save_inventory_to(&store, store_path)?;
    }

    Ok(CleanupSummary {
        present_count: present,
        missing_count: missing,
        removed_count: removed,
        missing_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests exercise the `_at` variants with an explicit temp path so
    // they do not touch the process-global HOME env var. This keeps them
    // independent of any other tests that mutate HOME, so cargo test can
    // run modules in parallel without races.

    fn tmp_store() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted-inventory.json");
        (dir, path)
    }

    #[test]
    fn test_register_and_list() {
        let (_dir, store_path) = tmp_store();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let entry = register_at(&store_path, &path, "my-folder", 5, 1024).unwrap();
        assert_eq!(entry.folder_name, "my-folder");
        assert_eq!(entry.file_count, 5);

        let list = list_with_existence_at(&store_path);
        assert_eq!(list.len(), 1);
        assert!(list[0].1);
    }

    #[test]
    fn test_register_deduplicates_on_path() {
        let (_dir, store_path) = tmp_store();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        register_at(&store_path, &path, "folder1", 3, 500).unwrap();
        register_at(&store_path, &path, "folder1", 5, 700).unwrap();

        let list = list_with_existence_at(&store_path);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0.file_count, 5);
        assert_eq!(list[0].0.archive_size, 700);
    }

    #[test]
    fn test_cleanup_missing() {
        let (_dir, store_path) = tmp_store();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let existing = tmp.path().to_str().unwrap().to_string();

        register_at(&store_path, &existing, "real", 1, 10).unwrap();
        register_at(&store_path, "/nonexistent/fake.scrt4", "fake", 1, 10).unwrap();

        let summary = cleanup_at(&store_path, false).unwrap();
        assert_eq!(summary.present_count, 1);
        assert_eq!(summary.missing_count, 1);
        assert_eq!(summary.removed_count, 0);

        let summary = cleanup_at(&store_path, true).unwrap();
        assert_eq!(summary.present_count, 1);
        assert_eq!(summary.missing_count, 1);
        assert_eq!(summary.removed_count, 1);

        let list = list_with_existence_at(&store_path);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_unregister_by_id() {
        let (_dir, store_path) = tmp_store();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let entry = register_at(&store_path, &path, "x", 1, 1).unwrap();
        assert!(unregister_at(&store_path, &entry.id).unwrap());
        assert_eq!(list_with_existence_at(&store_path).len(), 0);
        assert!(!unregister_at(&store_path, "nonexistent").unwrap());
    }

    #[test]
    fn test_mark_decrypted() {
        let (_dir, store_path) = tmp_store();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        register_at(&store_path, &path, "x", 1, 1).unwrap();
        mark_decrypted_at(&store_path, &path).unwrap();
        let list = list_with_existence_at(&store_path);
        assert!(list[0].0.last_decrypted_at.is_some());

        // Silent no-op on unregistered path.
        mark_decrypted_at(&store_path, "/nonexistent").unwrap();
    }
}

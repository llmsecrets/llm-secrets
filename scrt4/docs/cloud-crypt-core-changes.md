# cloud-crypt — Core (TCB) extensions required

**Module:** `cloud-crypt` (non-TCB)
**Depends on:** small TCB changes in `daemon/src/encrypted_inventory.rs` + `daemon/src/handlers.rs`
**Filed:** 2026-04-17

The `cloud-crypt` module is pure orchestration. It does no crypto and
handles no keys. To finish the v1 feature set, Core needs two small
additions. Both are scoped, reviewable, and stay within the existing
`encrypted_inventory` pattern.

## 1. Schema: add `location` + `drive_file_id` to inventory entries

Current `EncryptedInventoryEntry` (see `encrypted_inventory.rs`) tracks:
- `id`, `folder_name`, `path`, `file_count`, `archive_size`, `created_at`

Add:

```rust
pub enum ArchiveLocation {
    Local,          // ciphertext on disk only
    Remote,         // ciphertext in remote storage only (local blob removed)
    Both,           // ciphertext on disk AND in remote storage
    Missing,        // path gone and no remote record
}

pub struct RemoteRef {
    pub provider: String,     // "gdrive" for v1; future: "s3", "onedrive"
    pub file_id:  String,     // provider-specific id
    pub synced_at: i64,       // unix seconds
}

// Added to EncryptedInventoryEntry:
pub location: ArchiveLocation,
pub remote:   Option<RemoteRef>,
```

Back-compat: default `location = Local` and `remote = None` for existing
entries on first read after upgrade. No migration needed for the on-disk
store — fields deserialize with defaults.

## 2. RPC: `inventory_set_location`

Single new RPC, handled in `daemon/src/handlers.rs`.

**Request:**
```json
{
  "method": "inventory_set_location",
  "params": {
    "id": "<archive-uuid>",
    "location": "both",              // "local" | "remote" | "both" | "missing"
    "remote": {                      // required when location != local|missing
      "provider": "gdrive",
      "file_id":  "1abcDEF..."
    }
  }
}
```

**Response:**
```json
{ "success": true, "data": { "id": "<archive-uuid>", "location": "both" } }
```

**Rules (daemon-side, non-negotiable):**

- Requires an unlocked session (same as every other write RPC).
- Only updates the metadata. Never reads or writes the ciphertext blob.
- If `id` is unknown → `{"success": false, "error": "unknown archive id"}`.
- `location == "remote"` is allowed even when the local blob is still on
  disk — the module may choose to call this after it has verified a
  successful upload and then deleted the local copy.
- The daemon does **not** validate `file_id` against any provider API.
  Trust boundary: the module asserts the upload happened, Core records it.

## 3. Surfacing in existing RPCs

Extend `list_encrypted` response entries with the new fields:

```jsonc
{
  "id": "...",
  "folder_name": "...",
  "path": "...",
  "file_count": 42,
  "archive_size": 12345,
  "exists": true,
  "location": "both",             // NEW
  "remote": {                     // NEW, nullable
    "provider": "gdrive",
    "file_id":  "1abc...",
    "synced_at": 1713398400
  }
}
```

`cleanup_encrypted` is unchanged — it still looks at `exists` (local
presence). A separate follow-up can add a "remote-only" cleanup pass
(call Drive API to verify the remote blob is still there), but that's
out of scope for this change.

## 4. What does NOT change in TCB

To keep review surface minimal:

- No new crypto code. Encryption/decryption paths are untouched.
- No session/auth changes. `inventory_set_location` uses the same
  `ensure_unlocked` guard as every other write RPC.
- No new dependencies. Pure struct + one handler + one RPC entry.
- No module-side key material. The module never holds a key — it
  only calls `list_encrypted` and `inventory_set_location`.

## 5. Review checklist

- [ ] `ArchiveLocation` + `RemoteRef` added with `serde(default)` for
      back-compat reads.
- [ ] `inventory_set_location` handler requires unlocked session.
- [ ] `list_encrypted` returns the new fields, defaulting when absent.
- [ ] Unit test: round-trip set_location → list_encrypted returns the
      stored location + remote ref.
- [ ] Unit test: set_location on unknown id returns a clean error, does
      not panic.
- [ ] Unit test: upgrade path — an entry serialized before this change
      deserializes with `location = Local, remote = None`.

## 6. After Core lands

Two tweaks in `daemon/bin/scrt4-modules/cloud-crypt.sh`:

1. After a successful upload in `_scrt4_cloud_crypt_push`, call
   `send_request` with `inventory_set_location` against each archive id
   so the daemon records `drive_file_id` + `location=both`. Remove the
   `# TODO: requires Core RPC ...` marker.
2. In `_scrt4_cloud_crypt_list`, replace `location_source: "pending-core"`
   with the actual `.location` / `.remote` fields from the RPC response.

No change to the module's declared reveals — still empty. This work
stays non-TCB.

use anyhow::{Context, Result};
use hivedb_core::{HiveDB, PutOptions, ScanOptions};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

/// Subdirectory of the db root that holds the HiveDB engine files.
const ENGINE_DIR: &str = "hivedb";
/// Where the pre-engine `<collection>/<id>.json` layout is moved after import.
const LEGACY_DIR: &str = "legacy_json";

/// Decode a percent-encoded filename component back to a logical doc id.
///
/// The legacy file store encoded ids (`:` and `/` are illegal in filenames
/// on Windows/NTFS or create subdirectories); the importer needs the inverse
/// to recover the original id from `<id>.json`.
fn decode_id(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(v) = u8::from_str_radix(&name[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// hiveCyber's document store: a thin async facade over the HiveDB engine
/// (`hivedb-core`, redb-backed collections + hybrid BM25/ANN index).
///
/// The facade keeps the original `insert/get/delete/list/count` surface so
/// callers are unchanged; the engine's richer API (secondary indexes, scans,
/// atomic batches, semantic search, event log) is reachable via [`HiveDb::engine`].
#[derive(Clone)]
pub struct HiveDb {
    engine: Arc<HiveDB>,
}

impl HiveDb {
    /// Open (creating if needed) the database rooted at `base_dir`, importing
    /// any legacy `<collection>/<id>.json` files left by the file-based store.
    pub async fn open(base_dir: &Path) -> Result<Self> {
        fs::create_dir_all(base_dir).await.context("create db dir")?;

        let engine_path = base_dir.join(ENGINE_DIR);
        let engine = tokio::task::spawn_blocking(move || HiveDB::open(engine_path))
            .await
            .context("hivedb open task")?
            .context("open hivedb engine")?;
        let db = HiveDb {
            engine: Arc::new(engine),
        };

        db.import_legacy(base_dir).await?;
        Ok(db)
    }

    /// Direct access to the engine for features beyond the document facade
    /// (semantic index, secondary indexes, event log, projections).
    pub fn engine(&self) -> &Arc<HiveDB> {
        &self.engine
    }

    /// Run a blocking engine call off the async runtime.
    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&HiveDB) -> hivedb_core::HiveResult<T> + Send + 'static,
    {
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || f(&engine))
            .await
            .context("hivedb task")?
            .map_err(anyhow::Error::from)
    }

    /// One-shot, idempotent import of the legacy JSON-file layout. Each
    /// collection directory is imported with upserts, then moved under
    /// `legacy_json/` as a backup so it is never imported twice.
    async fn import_legacy(&self, base_dir: &Path) -> Result<()> {
        let mut entries = fs::read_dir(base_dir).await.context("read db dir")?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if !path.is_dir() || name == ENGINE_DIR || name == LEGACY_DIR {
                continue;
            }
            let imported = self.import_legacy_collection(&name, &path).await?;
            if imported == 0 {
                continue;
            }
            tracing::info!(collection = %name, docs = imported, "imported legacy json collection");
            let backup_root = base_dir.join(LEGACY_DIR);
            fs::create_dir_all(&backup_root).await?;
            let mut dest = backup_root.join(&name);
            if dest.exists() {
                dest = backup_root.join(format!("{name}-{}", uuid::Uuid::new_v4()));
            }
            fs::rename(&path, &dest).await.context("backup legacy collection")?;
        }
        Ok(())
    }

    async fn import_legacy_collection(&self, collection: &str, dir: &PathBuf) -> Result<usize> {
        let mut docs: Vec<(String, Value)> = Vec::new();
        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let id = decode_id(&path.file_stem().unwrap_or_default().to_string_lossy());
            match fs::read_to_string(&path)
                .await
                .map_err(anyhow::Error::from)
                .and_then(|s| serde_json::from_str::<Value>(&s).map_err(anyhow::Error::from))
            {
                Ok(doc) => docs.push((id, doc)),
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "skipping unreadable legacy doc"),
            }
        }
        let count = docs.len();
        if count == 0 {
            return Ok(0);
        }
        let collection = collection.to_string();
        self.run(move |db| {
            for (id, doc) in &docs {
                db.col_put(&collection, id, doc, PutOptions::default())?;
            }
            Ok(())
        })
        .await?;
        Ok(count)
    }

    /// Insert or replace a document (unconditional upsert).
    pub async fn insert(&self, collection: &str, id: &str, data: Value) -> Result<()> {
        let (collection, id) = (collection.to_string(), id.to_string());
        self.run(move |db| db.col_put(&collection, &id, &data, PutOptions::default()))
            .await
            .map(|_| ())
    }

    pub async fn get(&self, collection: &str, id: &str) -> Option<Value> {
        let (c, i) = (collection.to_string(), id.to_string());
        match self.run(move |db| db.col_get(&c, &i)).await {
            Ok(entry) => entry.map(|e| e.doc),
            Err(e) => {
                tracing::warn!(collection, id, error = %e, "hivedb get failed");
                None
            }
        }
    }

    pub async fn delete(&self, collection: &str, id: &str) -> Result<()> {
        let (collection, id) = (collection.to_string(), id.to_string());
        self.run(move |db| db.col_delete(&collection, &id))
            .await
            .map(|_| ())
    }

    /// All documents of a collection, ordered by id.
    pub async fn list(&self, collection: &str) -> Vec<(String, Value)> {
        let c = collection.to_string();
        match self
            .run(move |db| db.col_scan(&c, &ScanOptions::default()))
            .await
        {
            Ok(entries) => entries.into_iter().map(|e| (e.id, e.doc)).collect(),
            Err(e) => {
                tracing::warn!(collection, error = %e, "hivedb list failed");
                Vec::new()
            }
        }
    }

    pub async fn count(&self, collection: &str) -> usize {
        let c = collection.to_string();
        match self.run(move |db| db.col_count(&c)).await {
            Ok(n) => n as usize,
            Err(e) => {
                tracing::warn!(collection, error = %e, "hivedb count failed");
                0
            }
        }
    }

    /// Create an equality index on a top-level field (optionally unique).
    /// Idempotent for an already-existing index.
    pub async fn create_index(&self, collection: &str, field: &str, unique: bool) -> Result<()> {
        let (c, f) = (collection.to_string(), field.to_string());
        self.run(move |db| db.col_create_index(&c, &f, unique)).await
    }

    /// Documents whose indexed top-level `field` equals `value`, ordered by id.
    pub async fn find_by(
        &self,
        collection: &str,
        field: &str,
        value: Value,
    ) -> Result<Vec<(String, Value)>> {
        let (c, f) = (collection.to_string(), field.to_string());
        let entries = self
            .run(move |db| db.col_find_by(&c, &f, &value, &ScanOptions::default()))
            .await?;
        Ok(entries.into_iter().map(|e| (e.id, e.doc)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hc_{tag}_{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn decode_recovers_percent_encoded_ids() {
        assert_eq!(
            decode_id("openrouter%3A%3Aanthropic%2Fclaude-opus-5"),
            "openrouter::anthropic/claude-opus-5"
        );
        assert_eq!(decode_id("plain-id_1.0"), "plain-id_1.0");
    }

    #[tokio::test]
    async fn insert_id_with_colon_and_slash_roundtrips_and_reopens() {
        let dir = tmp("enc");
        let id = "openrouter::anthropic/claude-opus-5";
        {
            let db = HiveDb::open(&dir).await.unwrap();
            db.insert("models", id, serde_json::json!({ "ctx": 1_000_000 }))
                .await
                .expect("insert with ':' and '/' must succeed on any OS");
            assert!(db.get("models", id).await.is_some(), "get by logical id");
            let items = db.list("models").await;
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, id, "list recovers the exact logical id");
        }
        let db2 = HiveDb::open(&dir).await.unwrap();
        assert!(db2.get("models", id).await.is_some(), "id survives a reopen");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn insert_overwrites_delete_removes_and_count_tracks() {
        let dir = tmp("crud");
        let db = HiveDb::open(&dir).await.unwrap();
        db.insert("c", "a", serde_json::json!({ "v": 1 })).await.unwrap();
        db.insert("c", "a", serde_json::json!({ "v": 2 })).await.unwrap();
        db.insert("c", "b", serde_json::json!({ "v": 3 })).await.unwrap();
        assert_eq!(db.count("c").await, 2);
        assert_eq!(db.get("c", "a").await.unwrap()["v"], 2);
        db.delete("c", "a").await.unwrap();
        db.delete("c", "missing").await.unwrap();
        assert_eq!(db.count("c").await, 1);
        assert_eq!(db.count("nope").await, 0);
        assert!(db.get("nope", "x").await.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn find_by_uses_secondary_index() {
        let dir = tmp("idx");
        let db = HiveDb::open(&dir).await.unwrap();
        db.create_index("jobs", "status", false).await.unwrap();
        db.insert("jobs", "1", serde_json::json!({ "status": "queued" })).await.unwrap();
        db.insert("jobs", "2", serde_json::json!({ "status": "done" })).await.unwrap();
        db.insert("jobs", "3", serde_json::json!({ "status": "queued" })).await.unwrap();
        let queued = db.find_by("jobs", "status", serde_json::json!("queued")).await.unwrap();
        let ids: Vec<_> = queued.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["1", "3"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn legacy_json_layout_is_imported_once_and_backed_up() {
        let dir = tmp("legacy");
        let col = dir.join("models");
        std::fs::create_dir_all(&col).unwrap();
        std::fs::write(
            col.join("openrouter%3A%3Aanthropic%2Fclaude-opus-5.json"),
            r#"{"ctx": 1000000}"#,
        )
        .unwrap();
        std::fs::write(col.join("broken.json"), "{not json").unwrap();

        let db = HiveDb::open(&dir).await.unwrap();
        let doc = db.get("models", "openrouter::anthropic/claude-opus-5").await;
        assert_eq!(doc.unwrap()["ctx"], 1_000_000);
        assert_eq!(db.count("models").await, 1, "unreadable doc is skipped");
        assert!(!col.exists(), "legacy dir moved out of the way");
        assert!(dir.join(LEGACY_DIR).join("models").exists(), "backup kept");
        drop(db);

        // Reopen: nothing re-imported, data still there.
        let db2 = HiveDb::open(&dir).await.unwrap();
        assert_eq!(db2.count("models").await, 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}

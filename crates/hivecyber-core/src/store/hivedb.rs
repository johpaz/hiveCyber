use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doc {
    pub id: String,
    #[serde(flatten)]
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

/// Map a logical doc id to a filesystem-safe filename component, and back. Doc
/// ids legitimately contain characters that are illegal in filenames — `:` (the
/// `namespace::key` / `provider::model` separator, reserved on Windows/NTFS) and
/// `/` (inside model ids like `openrouter::anthropic/claude-opus-5`, which would
/// otherwise create subdirectories). Percent-encoding everything outside a safe
/// set makes storage work identically on Linux, macOS and Windows and stays
/// reversible so `list()` recovers the original id.
fn encode_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for b in id.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

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

#[derive(Clone)]
pub struct HiveDb {
    base_dir: PathBuf,
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    collections: HashMap<String, Collection>,
}

struct Collection {
    docs: HashMap<String, Value>,
    index_by_field: HashMap<String, BTreeMap<String, Vec<String>>>,
}

impl HiveDb {
    pub async fn open(base_dir: &Path) -> Result<Self> {
        fs::create_dir_all(base_dir).await.context("create db dir")?;

        let mut collections = HashMap::new();

        if let Ok(mut entries) = fs::read_dir(base_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_dir() {
                    let col_name = path
                        .file_name()
                        .context("collection name")?
                        .to_string_lossy()
                        .to_string();
                    let col = Self::load_collection(&path).await;
                    collections.insert(col_name, col);
                }
            }
        }

        Ok(HiveDb {
            base_dir: base_dir.to_path_buf(),
            inner: Arc::new(RwLock::new(Inner { collections })),
        })
    }

    async fn load_collection(dir: &Path) -> Collection {
        let mut docs = HashMap::new();
        let mut index_by_field = HashMap::new();

        if let Ok(mut entries) = fs::read_dir(dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let id = decode_id(&path.file_stem().unwrap_or_default().to_string_lossy());
                    if let Ok(content) = fs::read_to_string(&path).await {
                        if let Ok(doc) = serde_json::from_str::<Value>(&content) {
                            Self::index_doc(&id, &doc, &mut index_by_field);
                            docs.insert(id, doc);
                        }
                    }
                }
            }
        }

        Collection {
            docs,
            index_by_field,
        }
    }

    fn index_doc(id: &str, doc: &Value, index: &mut HashMap<String, BTreeMap<String, Vec<String>>>) {
        if let Some(obj) = doc.as_object() {
            for (key, val) in obj {
                if let Some(s) = val.as_str() {
                    index
                        .entry(key.clone())
                        .or_default()
                        .entry(s.to_string())
                        .or_default()
                        .push(id.to_string());
                }
            }
        }
    }

    pub async fn insert(&self, collection: &str, id: &str, data: Value) -> Result<()> {
        let file_path = self.base_dir.join(collection).join(format!("{}.json", encode_id(id)));
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let json = serde_json::to_string_pretty(&data)?;
        let tmp = file_path.with_extension("json.tmp");
        fs::write(&tmp, &json).await?;
        fs::rename(&tmp, &file_path).await?;

        let mut inner = self.inner.write().await;
        let col = inner
            .collections
            .entry(collection.to_string())
            .or_insert_with(|| Collection {
                docs: HashMap::new(),
                index_by_field: HashMap::new(),
            });

        if let Some(old) = col.docs.remove(id) {
            if let Some(old_obj) = old.as_object() {
                for (key, val) in old_obj {
                    if let Some(s) = val.as_str() {
                        if let Some(tree) = col.index_by_field.get_mut(key) {
                            if let Some(ids) = tree.get_mut(s) {
                                ids.retain(|x| x != id);
                            }
                        }
                    }
                }
            }
        }

        Self::index_doc(id, &data, &mut col.index_by_field);
        col.docs.insert(id.to_string(), data);

        Ok(())
    }

    pub async fn get(&self, collection: &str, id: &str) -> Option<Value> {
        let inner = self.inner.read().await;
        inner
            .collections
            .get(collection)
            .and_then(|c| c.docs.get(id).cloned())
    }

    pub async fn delete(&self, collection: &str, id: &str) -> Result<()> {
        let file_path = self.base_dir.join(collection).join(format!("{}.json", encode_id(id)));
        if file_path.exists() {
            fs::remove_file(&file_path).await?;
        }

        let mut inner = self.inner.write().await;
        if let Some(col) = inner.collections.get_mut(collection) {
            if let Some(doc) = col.docs.remove(id) {
                if let Some(obj) = doc.as_object() {
                    for (key, val) in obj {
                        if let Some(s) = val.as_str() {
                            if let Some(tree) = col.index_by_field.get_mut(key) {
                                if let Some(ids) = tree.get_mut(s) {
                                    ids.retain(|x| x != id);
                                    if ids.is_empty() {
                                        tree.remove(s);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn list(&self, collection: &str) -> Vec<(String, Value)> {
        let inner = self.inner.read().await;
        inner
            .collections
            .get(collection)
            .map(|c| {
                let mut items: Vec<(String, Value)> =
                    c.docs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                items.sort_by(|a, b| a.0.cmp(&b.0));
                items
            })
            .unwrap_or_default()
    }

    pub async fn count(&self, collection: &str) -> usize {
        let inner = self.inner.read().await;
        inner
            .collections
            .get(collection)
            .map(|c| c.docs.len())
            .unwrap_or(0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_yields_safe_filename_and_roundtrips() {
        // Ids that contain filename-illegal chars on Windows (`:`) or path
        // separators (`/`), plus a plain one.
        for id in [
            "anthropic::claude-sonnet-5",
            "openrouter::anthropic/claude-opus-5",
            "recon::host-a",
            "hiveagents::Qwen3.6-35B-A3B-UD-Q4_K_M.gguf",
            "plain-id_1.0",
        ] {
            let enc = encode_id(id);
            assert!(
                !enc.contains(':') && !enc.contains('/') && !enc.contains('\\'),
                "encoded '{}' still has an unsafe char: {}",
                id,
                enc
            );
            assert_eq!(decode_id(&enc), id, "roundtrip failed for {}", id);
        }
    }

    #[tokio::test]
    async fn insert_id_with_colon_and_slash_roundtrips_and_reopens() {
        let dir = std::env::temp_dir().join(format!("hc_enc_{}", uuid::Uuid::new_v4()));
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
        // Reopen from disk → decode must recover the id.
        let db2 = HiveDb::open(&dir).await.unwrap();
        assert!(db2.get("models", id).await.is_some(), "id survives a reopen");
        std::fs::remove_dir_all(&dir).ok();
    }
}

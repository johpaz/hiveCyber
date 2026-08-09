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
                    let id = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
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
        let file_path = self.base_dir.join(collection).join(format!("{}.json", id));
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
        let file_path = self.base_dir.join(collection).join(format!("{}.json", id));
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
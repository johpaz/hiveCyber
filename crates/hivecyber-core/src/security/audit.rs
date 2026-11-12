use std::sync::OnceLock;

use anyhow::Result;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::store::HiveDb;
use crate::store::collections::{COL_AUDIT_LOG, AuditLogEntry};

pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Process-global lock serializing the read-head + append critical section of
/// the audit chain. Without it, two concurrent workers can both read the same
/// `prev_hash`, build different entries, and fork the chain. The audit log is a
/// single collection under a single `HIVECYBER_HOME`, and every write happens in
/// the orchestrator process, so one process-wide lock is the right granularity.
/// (Cross-process writers against the same home would need an OS file lock — out
/// of scope for the single-process agent runtime.)
fn audit_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Atomically extend the audit chain. Under the global audit lock: read the
/// current head hash and append a new entry chained to it, returning the new
/// head. This is the ONLY correct way to append — callers must not interleave
/// their own `get_last_hash` + `log_audit`, which is exactly the race this
/// closes.
pub async fn append_audit(
    db: &HiveDb,
    tool: &str,
    target: &str,
    worker: &str,
    run_id: &str,
    operator_id: &str,
) -> Result<String> {
    append_audit_in(
        db,
        db.shared_state_dir().as_deref(),
        tool,
        target,
        worker,
        run_id,
        operator_id,
    )
    .await
}

/// Cabecera de la cadena compartida entre procesos: `"<n_entradas> <hash>"`.
fn read_head(dir: &std::path::Path) -> Option<(usize, String)> {
    let s = std::fs::read_to_string(dir.join("audit.head")).ok()?;
    let (n, h) = s.trim().split_once(' ')?;
    Some((n.parse().ok()?, h.to_string()))
}

fn write_head(dir: &std::path::Path, n: usize, hash: &str) -> Result<()> {
    let tmp = dir.join("audit.head.tmp");
    std::fs::write(&tmp, format!("{} {}", n, hash))?;
    std::fs::rename(&tmp, dir.join("audit.head"))?;
    Ok(())
}

/// Núcleo de `append_audit`. Con `state` (HIVECYBER_HOME configurado) añade,
/// además del lock en proceso, un lock de archivo del SO y una cabecera
/// `count hash`, para que dos procesos sobre el mismo home no bifurquen la
/// cadena. Falla CERRADO si la vista de la BD de este proceso está por detrás
/// de la cabecera (otro proceso añadió entradas que aún no vemos).
pub(crate) async fn append_audit_in(
    db: &HiveDb,
    state: Option<&std::path::Path>,
    tool: &str,
    target: &str,
    worker: &str,
    run_id: &str,
    operator_id: &str,
) -> Result<String> {
    let _guard = audit_lock().lock().await;

    let Some(dir) = state else {
        let prev = get_last_hash(db).await;
        return log_audit(db, tool, target, worker, run_id, operator_id, &prev).await;
    };

    let dir_owned = dir.to_path_buf();
    let _file_lock = tokio::task::spawn_blocking(move || {
        hivecyber_tools::shared_state::acquire_lock(&dir_owned, "audit.lock")
    })
    .await
    .map_err(|e| anyhow::anyhow!("audit lock task: {}", e))?
    .map_err(|e| anyhow::anyhow!("audit file lock: {}", e))?;

    let n = db.count(COL_AUDIT_LOG).await;
    let prev = match read_head(dir) {
        // Vista consistente con la cabecera.
        Some((c, h)) if c == n => h,
        // La cabecera está por delante de lo que vemos: otro proceso escribió
        // (o la BD se restauró). No adivinar: rechazar y auditar el motivo.
        Some((c, _)) if c > n => {
            return Err(anyhow::anyhow!(
                "audit head ({} entradas) por delante de la vista de la BD ({}): \
                 otro proceso escribió o la BD cambió; reinicia el proceso, o borra \
                 state/audit.head si reiniciaste la BD a propósito",
                c, n
            ));
        }
        // Sin cabecera (primera vez / versión previa) o BD por delante.
        _ => get_last_hash(db).await,
    };
    let new_hash = log_audit(db, tool, target, worker, run_id, operator_id, &prev).await?;
    write_head(dir, n + 1, &new_hash)?;
    Ok(new_hash)
}

/// SHA-256 over the entry's canonical field order. Single source of truth so
/// `log_audit`, `get_last_hash`, and `verify_chain` can never drift.
fn entry_hash(e: &AuditLogEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(e.hash_chain_prev.as_bytes());
    hasher.update(e.timestamp.as_bytes());
    hasher.update(e.tool.as_bytes());
    hasher.update(e.target.as_bytes());
    hasher.update(e.worker.as_bytes());
    hasher.update(e.run_id.as_bytes());
    hasher.update(e.operator_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Total order over audit entries: chronological, with the id as tiebreaker.
/// **Both** the writer (`get_last_hash`) and the verifier (`verify_chain`) must
/// use this exact order — `db.list` returns entries sorted by id (UUID), which
/// is NOT chronological, so relying on `list().last()` picked the wrong "prev"
/// once ids stopped sorting in insertion order and broke the chain.
fn sorted_entries(mut entries: Vec<(String, serde_json::Value)>) -> Vec<(String, serde_json::Value)> {
    entries.sort_by(|a, b| {
        let ts_a = a.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.1.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_a.cmp(ts_b).then_with(|| a.0.cmp(&b.0))
    });
    entries
}

pub async fn log_audit(
    db: &HiveDb,
    tool: &str,
    target: &str,
    worker: &str,
    run_id: &str,
    operator_id: &str,
    prev_hash: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let entry = AuditLogEntry {
        id: id.clone(),
        timestamp,
        tool: tool.into(),
        target: target.into(),
        worker: worker.into(),
        run_id: run_id.into(),
        operator_id: operator_id.into(),
        hash_chain_prev: prev_hash.into(),
    };
    let current_hash = entry_hash(&entry);

    db.insert(COL_AUDIT_LOG, &id, serde_json::to_value(&entry)?).await?;
    Ok(current_hash)
}

pub async fn get_last_hash(db: &HiveDb) -> String {
    let entries = sorted_entries(db.list(COL_AUDIT_LOG).await);
    entries
        .last()
        .and_then(|(_, v)| serde_json::from_value::<AuditLogEntry>(v.clone()).ok())
        .map(|e| entry_hash(&e))
        .unwrap_or_else(|| GENESIS_HASH.to_string())
}

pub async fn verify_chain(db: &HiveDb) -> Result<(bool, Vec<String>)> {
    let entries = sorted_entries(db.list(COL_AUDIT_LOG).await);

    let mut errors = Vec::new();
    let mut prev_hash = GENESIS_HASH.to_string();

    for (id, val) in &entries {
        let entry: AuditLogEntry = match serde_json::from_value(val.clone()) {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("entry {}: parse error: {}", id, e));
                continue;
            }
        };

        if entry.hash_chain_prev != prev_hash {
            errors.push(format!(
                "entry {}: hash chain broken (expected {} got {})",
                id, prev_hash, entry.hash_chain_prev
            ));
        }

        prev_hash = entry_hash(&entry);
    }

    Ok((errors.is_empty(), errors))
}
#[cfg(test)]
mod shared_state_tests {
    use super::*;

    async fn db_and_state() -> (HiveDb, tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let state = t.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let db = HiveDb::open(&t.path().join("db")).await.unwrap();
        (db, t, state)
    }

    #[tokio::test]
    async fn concurrent_appends_with_file_lock_keep_chain_valid_and_head_in_sync() {
        let (db, _t, state) = db_and_state().await;
        let mut hs = Vec::new();
        for i in 0..32 {
            let (db, state) = (db.clone(), state.clone());
            hs.push(tokio::spawn(async move {
                append_audit_in(&db, Some(&state), "nmap", &format!("10.0.0.{i}"), "w", "run", "op")
                    .await
                    .unwrap()
            }));
        }
        for h in hs {
            h.await.unwrap();
        }
        let (ok, errs) = verify_chain(&db).await.unwrap();
        assert!(ok, "{errs:?}");
        let (n, h) = read_head(&state).unwrap();
        assert_eq!(n, 32);
        assert_eq!(h, get_last_hash(&db).await);
    }

    #[tokio::test]
    async fn stale_view_behind_head_fails_closed() {
        let (db, _t, state) = db_and_state().await;
        append_audit_in(&db, Some(&state), "a", "t", "w", "r", "o").await.unwrap();
        // Otro proceso añadió 5 entradas que este proceso aún no ve.
        write_head(&state, 6, "deadbeef").unwrap();
        let err = append_audit_in(&db, Some(&state), "b", "t", "w", "r", "o").await.unwrap_err();
        assert!(err.to_string().contains("por delante"), "{err}");
        // y no escribió nada
        assert_eq!(db.count(COL_AUDIT_LOG).await, 1);
    }

    #[tokio::test]
    async fn without_state_dir_behaves_as_before() {
        let (db, _t, _s) = db_and_state().await;
        append_audit_in(&db, None, "a", "t", "w", "r", "o").await.unwrap();
        append_audit_in(&db, None, "b", "t", "w", "r", "o").await.unwrap();
        assert!(verify_chain(&db).await.unwrap().0);
    }
}

//! Estado compartido ENTRE PROCESOS bajo `$HIVECYBER_HOME/state/`.
//!
//! Dos procesos sobre el mismo home (p. ej. `daemon` + `run`) no comparten la
//! memoria de los limitadores ni el lock en proceso de la cadena de audit.
//! Estas primitivas usan locks de archivo del SO (`File::lock`, std ≥ 1.89) y
//! fallan CERRADO: si el estado compartido está configurado pero no se puede
//! leer/escribir, la operación se rechaza.
//!
//! Dentro del worker sandboxeado (`HIVECYBER_IN_WORKER=1`) no se usa: el
//! orquestador aplica el rate limit antes de despachar y el sandbox oculta el
//! home.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Directorio de estado compartido, o `None` si no aplica (sin
/// `HIVECYBER_HOME`, o dentro del worker): se usa solo el limitador en proceso.
pub fn state_dir() -> Option<PathBuf> {
    if std::env::var_os("HIVECYBER_IN_WORKER").is_some() {
        return None;
    }
    let home = std::env::var_os("HIVECYBER_HOME")?;
    let dir = PathBuf::from(home).join("state");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn sanitize(key: &str) -> String {
    let s: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .take(120)
        .collect();
    format!("rl-{}", s)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Rate limit entre procesos: permite UNA petición por `min_interval` por
/// `key`. Lectura-comprobación-escritura bajo lock exclusivo del archivo.
pub fn file_rate_check(dir: &Path, key: &str, min_interval: Duration) -> Result<(), String> {
    let path = dir.join(sanitize(key));
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("estado de rate limit ilegible ({}): {}", path.display(), e))?;
    f.lock().map_err(|e| format!("lock de rate limit falló: {}", e))?;

    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| format!("lectura de rate limit: {}", e))?;
    let now = now_ms();
    if let Ok(last) = s.trim().parse::<u64>() {
        if now.saturating_sub(last) < min_interval.as_millis() as u64 {
            return Err(format!(
                "rate limit excedido (compartido entre procesos) para '{}'",
                key
            ));
        }
    }
    f.set_len(0).map_err(|e| format!("rate limit: {}", e))?;
    f.seek(SeekFrom::Start(0)).map_err(|e| format!("rate limit: {}", e))?;
    f.write_all(now.to_string().as_bytes())
        .map_err(|e| format!("rate limit: {}", e))?;
    Ok(()) // el lock se libera al soltar `f`
}

/// Lock exclusivo bloqueante sobre `<dir>/<name>`; se mantiene mientras el
/// `File` devuelto siga vivo. Llamar desde `spawn_blocking` en contexto async.
pub fn acquire_lock(dir: &Path, name: &str) -> std::io::Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(name))?;
    f.lock()?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("hc-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn second_request_inside_interval_is_refused_then_allowed() {
        let d = tmp();
        let iv = Duration::from_millis(150);
        assert!(file_rate_check(&d, "prog::a.com", iv).is_ok());
        assert!(file_rate_check(&d, "prog::a.com", iv).is_err());
        assert!(file_rate_check(&d, "prog::b.com", iv).is_ok(), "otra clave es independiente");
        std::thread::sleep(Duration::from_millis(200));
        assert!(file_rate_check(&d, "prog::a.com", iv).is_ok());
    }

    #[test]
    fn concurrent_callers_get_exactly_one_slot() {
        // Cada hilo abre su propio descriptor: el lock del SO los serializa igual
        // que a procesos distintos.
        let d = Arc::new(tmp());
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let d = d.clone();
                std::thread::spawn(move || file_rate_check(&d, "p::h", Duration::from_secs(5)).is_ok())
            })
            .collect();
        let ok = handles.into_iter().filter_map(|h| h.join().ok()).filter(|x| *x).count();
        assert_eq!(ok, 1);
    }
}

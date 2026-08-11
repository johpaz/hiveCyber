//! Encrypted secret storage (AES-256-GCM).
//!
//! Rust port of Hive's `packages/core/src/storage/crypto.ts`. Secrets (provider
//! API keys, etc.) are encrypted at rest with a 256-bit master key and stored in
//! `COL_SECRETS`. The master key comes from `HIVECYBER_MASTER_KEY` (base64 or hex
//! of 32 bytes) or a `<home>/.master.key` file (32 raw bytes, mode 0600),
//! generated on first use.
//!
//! Wire format per secret value: base64( nonce[12] || ciphertext+tag ).

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;

use crate::store::HiveDb;
use crate::store::collections::COL_SECRETS;

/// Holds the master key and provides encrypt/decrypt + a secret store bound to a
/// `HiveDb`.
pub struct SecretStore {
    key: [u8; 32],
}

impl SecretStore {
    /// Open the store for a given hivecyber home, loading or creating the master
    /// key. `HIVECYBER_MASTER_KEY` (if set) always wins over the on-disk file.
    pub fn open(home: &str) -> Result<Self> {
        let key = load_or_create_master_key(home)?;
        Ok(SecretStore { key })
    }

    /// Construct directly from a 32-byte key (tests).
    pub fn from_key(key: [u8; 32]) -> Self {
        SecretStore { key }
    }

    /// Encrypt a UTF-8 string → base64(nonce || ciphertext).
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt failed: {}", e))?;
        let mut out = Vec::with_capacity(nonce.len() + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(B64.encode(out))
    }

    /// Decrypt a base64(nonce || ciphertext) blob back to the original string.
    pub fn decrypt(&self, blob: &str) -> Result<String> {
        let raw = B64.decode(blob.trim()).context("secret is not valid base64")?;
        if raw.len() < 12 + 16 {
            anyhow::bail!("secret blob too short");
        }
        let (nonce_bytes, ct) = raw.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let pt = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct)
            .map_err(|_| anyhow::anyhow!("decrypt failed (wrong master key or corrupt secret)"))?;
        String::from_utf8(pt).context("decrypted secret is not UTF-8")
    }

    /// Encrypt `value` and upsert it under `name` in `COL_SECRETS`.
    pub async fn store(&self, db: &HiveDb, name: &str, value: &str) -> Result<()> {
        let enc = self.encrypt(value)?;
        let doc = serde_json::json!({
            "id": name,
            "value": enc,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        db.insert(COL_SECRETS, name, doc).await
    }

    /// Load and decrypt the secret `name`, if present.
    pub async fn load(&self, db: &HiveDb, name: &str) -> Option<String> {
        let doc = db.get(COL_SECRETS, name).await?;
        let blob = doc.get("value").and_then(|v| v.as_str())?;
        match self.decrypt(blob) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!("could not decrypt secret '{}': {}", name, e);
                None
            }
        }
    }
}

/// The stored-secret key for a provider's API key.
pub fn provider_key_name(provider_id: &str) -> String {
    format!("provider:{}:api_key", provider_id)
}

/// Resolve a provider API key: the environment variable wins (explicit
/// override), otherwise the encrypted secret store (`provider set` persists keys
/// there, so a configured host runs with no env vars). Empty when neither has it.
pub async fn resolve_api_key(db: &HiveDb, home: &str, provider_id: &str) -> String {
    if let Some(k) = hivecyber_providers::ProviderRegistry::get_default_api_key(provider_id) {
        if !k.is_empty() {
            return k;
        }
    }
    if let Ok(store) = SecretStore::open(home) {
        if let Some(k) = store.load(db, &provider_key_name(provider_id)).await {
            return k;
        }
    }
    String::new()
}

fn master_key_path(home: &str) -> PathBuf {
    Path::new(home).join(".master.key")
}

/// Resolve the 32-byte master key: env override, else the on-disk key file,
/// generating (0600) it if absent.
fn load_or_create_master_key(home: &str) -> Result<[u8; 32]> {
    if let Ok(env_key) = std::env::var("HIVECYBER_MASTER_KEY") {
        return parse_key_material(env_key.trim())
            .context("HIVECYBER_MASTER_KEY must be 32 bytes as base64 or hex");
    }

    let path = master_key_path(home);
    if path.exists() {
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() != 32 {
            anyhow::bail!("master key file {} is not 32 bytes", path.display());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Generate a fresh key and persist it 0600.
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, key).with_context(|| format!("write {}", path.display()))?;
    set_owner_only(&path);
    Ok(key)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) {}

/// Accept a 32-byte key as base64 (44 chars) or hex (64 chars).
fn parse_key_material(s: &str) -> Result<[u8; 32]> {
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .context("invalid hex")?
    } else {
        B64.decode(s).context("invalid base64")?
    };
    if bytes.len() != 32 {
        anyhow::bail!("key material must decode to 32 bytes (got {})", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let store = SecretStore::from_key([7u8; 32]);
        let secret = "sk-ant-super-secret-123";
        let blob = store.encrypt(secret).unwrap();
        assert_ne!(blob, secret, "ciphertext must not equal plaintext");
        assert_eq!(store.decrypt(&blob).unwrap(), secret);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let a = SecretStore::from_key([1u8; 32]);
        let b = SecretStore::from_key([2u8; 32]);
        let blob = a.encrypt("hello").unwrap();
        assert!(b.decrypt(&blob).is_err());
    }

    #[test]
    fn distinct_nonces_produce_distinct_ciphertexts() {
        let store = SecretStore::from_key([9u8; 32]);
        let a = store.encrypt("same").unwrap();
        let b = store.encrypt("same").unwrap();
        assert_ne!(a, b, "random nonce should make ciphertexts differ");
    }

    #[test]
    fn master_key_persists_across_opens() {
        let dir = std::env::temp_dir().join(format!("hc-crypto-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let home = dir.to_string_lossy().to_string();
        // Ensure env override is not interfering.
        unsafe {
            std::env::remove_var("HIVECYBER_MASTER_KEY");
        }
        let s1 = SecretStore::open(&home).unwrap();
        let blob = s1.encrypt("persisted").unwrap();
        let s2 = SecretStore::open(&home).unwrap();
        assert_eq!(s2.decrypt(&blob).unwrap(), "persisted");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_key_material_hex_and_base64() {
        let hex = "00".repeat(32);
        assert_eq!(parse_key_material(&hex).unwrap(), [0u8; 32]);
        let b64 = B64.encode([5u8; 32]);
        assert_eq!(parse_key_material(&b64).unwrap(), [5u8; 32]);
    }
}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::config::Config;

pub const DEFAULT_SESSION_TIMEOUT_MINUTES: u64 = 15;

pub struct ExploitSessionTracker {
    timeout: Duration,
    inner: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    worker_id: String,
    target: String,
    last_activity: Instant,
    paused: bool,
}

impl ExploitSessionTracker {
    pub fn new(config: &Config) -> Self {
        let minutes = if config.security.exploit_session_timeout_min > 0 {
            config.security.exploit_session_timeout_min
        } else {
            DEFAULT_SESSION_TIMEOUT_MINUTES
        };
        ExploitSessionTracker {
            timeout: Duration::from_secs(minutes * 60),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn record_activity(&self, worker_id: &str, target: &str) -> bool {
        let mut map = self.inner.lock().await;
        let key = format!("{}:{}", worker_id, target);
        let now = Instant::now();

        if let Some(session) = map.get_mut(&key) {
            if session.paused {
                tracing::warn!(
                    "exploit session paused for {} on {}; require --unsafe to resume",
                    worker_id,
                    target
                );
                return false;
            }
            session.last_activity = now;
            return true;
        }

        map.insert(
            key,
            Session {
                worker_id: worker_id.to_string(),
                target: target.to_string(),
                last_activity: now,
                paused: false,
            },
        );
        true
    }

    pub async fn check_timeouts(&self) -> Vec<String> {
        let mut paused_keys = Vec::new();
        let mut map = self.inner.lock().await;
        let now = Instant::now();
        for (key, session) in map.iter_mut() {
            if !session.paused && now.duration_since(session.last_activity) >= self.timeout {
                session.paused = true;
                tracing::warn!(
                    "exploit session paused for {} on {} (idle {}min)",
                    session.worker_id,
                    session.target,
                    self.timeout.as_secs() / 60
                );
                paused_keys.push(key.clone());
            }
        }
        paused_keys
    }

    pub async fn resume(&self, worker_id: &str, target: &str) -> bool {
        let mut map = self.inner.lock().await;
        let key = format!("{}:{}", worker_id, target);
        if let Some(session) = map.get_mut(&key) {
            session.paused = false;
            session.last_activity = Instant::now();
            return true;
        }
        false
    }

    pub async fn clear(&self, worker_id: &str, target: &str) {
        let mut map = self.inner.lock().await;
        let key = format!("{}:{}", worker_id, target);
        map.remove(&key);
    }

    pub async fn list_active(&self) -> Vec<(String, String, bool)> {
        let map = self.inner.lock().await;
        let result: Vec<(String, String, bool)> = map
            .values()
            .map(|s| (s.worker_id.clone(), s.target.clone(), s.paused))
            .collect();
        result
    }
}

pub async fn periodic_timeout_check(tracker: Arc<ExploitSessionTracker>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await;
    loop {
        interval.tick().await;
        let paused = tracker.check_timeouts().await;
        if !paused.is_empty() {
            tracing::info!("exploit session timeout check: {} session(s) paused", paused.len());
        }
    }
}
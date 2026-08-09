use crate::store::HiveDb;
use crate::store::collections::{COL_AGENTS, COL_AUDIT_LOG, AuditLogEntry};

pub async fn check_agent_enabled(db: &HiveDb, agent_id: &str) -> bool {
    db.get(COL_AGENTS, agent_id)
        .await
        .and_then(|v| v.get("enabled").and_then(|e| e.as_bool()))
        .unwrap_or(false)
}

pub async fn increment_harmful(db: &HiveDb, agent_id: &str) -> anyhow::Result<()> {
    let mut agent = db
        .get(COL_AGENTS, agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent not found"))?;

    if let Some(obj) = agent.as_object_mut() {
        let harmful = obj
            .get("harmful_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            + 1;
        obj.insert("harmful_count".into(), serde_json::json!(harmful));
        obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());

        let helpful = obj
            .get("helpful_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        if harmful >= 3 && harmful > helpful {
            obj.insert("enabled".into(), serde_json::json!(false));
        }

        if harmful >= 5 {
            obj.insert("enabled".into(), serde_json::json!(false));
            obj.insert("status".into(), serde_json::json!("auto_disabled"));
        }
    }

    db.insert(COL_AGENTS, agent_id, agent).await?;
    Ok(())
}

pub async fn increment_helpful(db: &HiveDb, agent_id: &str) -> anyhow::Result<()> {
    let mut agent = db
        .get(COL_AGENTS, agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("agent not found"))?;

    if let Some(obj) = agent.as_object_mut() {
        let helpful = obj
            .get("helpful_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            + 1;
        obj.insert("helpful_count".into(), serde_json::json!(helpful));
        obj.insert("updated_at".into(), chrono::Utc::now().to_rfc3339().into());
    }

    db.insert(COL_AGENTS, agent_id, agent).await?;
    Ok(())
}

pub fn validate_target_in_allowlist(target: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }

    for entry in allowlist {
        if entry.contains('/') {
            if let Some((net, bits)) = entry.split_once('/') {
                if let Ok(prefix) = net.parse::<std::net::IpAddr>() {
                    if let Ok(mask_len) = bits.parse::<u32>() {
                        if let Ok(ip) = target.parse::<std::net::IpAddr>() {
                            if ip_in_cidr(ip, prefix, mask_len) {
                                return true;
                            }
                        }
                    }
                }
            }
        } else if entry == target
            || target.ends_with(entry)
            || target == entry
        {
            return true;
        }
    }
    false
}

fn ip_in_cidr(ip: std::net::IpAddr, prefix: std::net::IpAddr, mask_len: u32) -> bool {
    let max_bits = match (&ip, &prefix) {
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => 32,
        (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => 128,
        _ => return false,
    };

    if mask_len > max_bits {
        return false;
    }

    match (ip, prefix, max_bits) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(net4), 32) => {
            let ip_int = u32::from(ip4);
            let net_int = u32::from(net4);
            let mask = if mask_len == 0 { 0 } else { !0u32 << (32 - mask_len) };
            (ip_int & mask) == net_int
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(net6), 128) => {
            let ip_bytes = ip6.octets();
            let net_bytes = net6.octets();
            let full_bytes = (mask_len / 8) as usize;
            let remaining_bits = mask_len % 8;

            if full_bytes > 0 {
                if ip_bytes[..full_bytes] != net_bytes[..full_bytes] {
                    return false;
                }
            }
            if remaining_bits > 0 {
                let mask = !0u8 << (8 - remaining_bits);
                if (ip_bytes[full_bytes] & mask) != (net_bytes[full_bytes] & mask) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}
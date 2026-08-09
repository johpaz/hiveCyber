use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::base;
use crate::recon;

#[derive(Debug, Clone, Default)]
pub struct SecurityContext {
    pub unsafe_mode: bool,
    pub allowlist_hosts: Vec<String>,
    pub operator_id: String,
}

impl SecurityContext {
    pub fn validate_target(&self, target: &str) -> Result<(), String> {
        if !self.unsafe_mode {
            return Err(format!(
                "unsafe_mode disabled — target '{}' requires --unsafe flag",
                target
            ));
        }
        if !validate_target_in_allowlist(target, &self.allowlist_hosts) {
            return Err(format!(
                "target '{}' not in allowlist (len={}) — use --allowlist-hosts",
                target,
                self.allowlist_hosts.len()
            ));
        }
        Ok(())
    }
}

fn validate_target_in_allowlist(target: &str, allowlist: &[String]) -> bool {
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
            if full_bytes > 0 && ip_bytes[..full_bytes] != net_bytes[..full_bytes] {
                return false;
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

#[derive(Debug, Clone, PartialEq)]
pub enum ToolCategory {
    Base,
    Recon,
    Vulns,
    Exploit,
    Forensics,
    Web,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Isolation {
    None,
    Sandbox,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> ToolCategory;
    fn parameters(&self) -> ToolSchema;
    fn main_thread_only(&self) -> bool {
        false
    }
    fn isolation(&self) -> Isolation {
        Isolation::None
    }
    async fn execute(&self, params: serde_json::Value) -> anyhow::Result<serde_json::Value>;
}

pub struct ToolRegistry {
    tools: HashMap<String, std::sync::Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        ToolRegistry {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: std::sync::Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&std::sync::Arc<dyn Tool>> {
        self.tools.get(name)
    }

    pub fn all(&self) -> Vec<&std::sync::Arc<dyn Tool>> {
        let mut tools: Vec<&std::sync::Arc<dyn Tool>> = self.tools.values().collect();
        tools.sort_by(|a, b| a.name().cmp(b.name()));
        tools
    }

    pub fn names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn filter_by_allowlist(&self, allowlist: &[String]) -> Vec<String> {
        let mut result = Vec::new();
        for pattern in allowlist {
            if pattern.contains('*') {
                let prefix = pattern.trim_end_matches('*');
                for name in self.tools.keys() {
                    if name.starts_with(prefix) {
                        result.push(name.clone());
                    }
                }
            } else if self.tools.contains_key(pattern) {
                result.push(pattern.clone());
            }
        }
        result
    }

    pub fn create_all() -> Self {
        Self::create_with_security(Arc::new(SecurityContext::default()))
    }

    pub fn create_with_security(security: Arc<SecurityContext>) -> Self {
        let mut reg = Self::new();

        let sec = security.clone();
        let base_tools: Vec<std::sync::Arc<dyn Tool>> = vec![
            std::sync::Arc::new(base::FsRead),
            std::sync::Arc::new(base::FsWrite),
            std::sync::Arc::new(base::FsEdit),
            std::sync::Arc::new(base::FsGlob),
            std::sync::Arc::new(base::FsExists),
            std::sync::Arc::new(base::WebFetch),
            std::sync::Arc::new(base::CliExec::new(sec.clone())),
        ];
        for tool in base_tools {
            reg.register(tool);
        }

        let recon_tools: Vec<std::sync::Arc<dyn Tool>> = vec![
            std::sync::Arc::new(recon::Nmap::new(sec.clone())),
            std::sync::Arc::new(recon::Dig),
            std::sync::Arc::new(recon::Whois),
            std::sync::Arc::new(recon::TheHarvester),
        ];
        for tool in recon_tools {
            reg.register(tool);
        }

        for tool in crate::vulns::create_all(sec.clone()) {
            reg.register(tool);
        }
        for tool in crate::exploit::create_all(sec.clone()) {
            reg.register(tool);
        }
        for tool in crate::forensics::create_all() {
            reg.register(tool);
        }

        reg
    }

    pub fn create_coordinator_registry() -> Self {
        Self::create_all()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
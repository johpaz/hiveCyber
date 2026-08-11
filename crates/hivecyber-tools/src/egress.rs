//! Kernel-level egress allowlist generated from an `EngagementPolicy`.
//!
//! Rationale: every shell-out tool funnels through `CliExec → bash → binary`,
//! and offensive tools open raw sockets (nmap SYN, hydra TCP, dig DNS) that an
//! HTTP proxy cannot see. The robust, protocol-agnostic control is a **default-
//! deny nftables egress firewall** applied at the container / network-namespace
//! boundary where hiveCyber runs — allowing only the engagement's authorized
//! targets, the DNS resolver, and explicitly-listed infrastructure (the LLM
//! provider, MCP servers, research endpoints). Enforced by the kernel, outside
//! the agent process — exactly the control an in-process check cannot guarantee.
//!
//! This module is pure (no network): `plan_from_policy` classifies the policy's
//! targets into v4/v6 literals/CIDRs (hostnames are surfaced for the caller to
//! resolve), and `nftables_ruleset` renders the `nft -f` script.

use std::net::IpAddr;

use crate::engagement::EngagementPolicy;

/// A resolved egress allowlist ready to render as nftables rules.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EgressPlan {
    pub program: String,
    /// IPv4 addresses / CIDRs to allow as destinations.
    pub v4: Vec<String>,
    /// IPv6 addresses / CIDRs to allow as destinations.
    pub v6: Vec<String>,
    /// DNS resolver IPs. Empty → DNS (port 53) is allowed to any destination
    /// (needed to resolve target hostnames), with a warning comment.
    pub resolvers: Vec<String>,
    /// Hostnames from the policy that must be resolved to IPs by the caller
    /// before the rules are complete (rendered as a warning comment).
    pub unresolved_hosts: Vec<String>,
}

impl EgressPlan {
    /// Add a destination (IP or CIDR); classifies it into the v4/v6 bucket, or
    /// records it as an unresolved hostname.
    pub fn add_destination(&mut self, entry: &str) {
        let entry = entry.trim();
        if entry.is_empty() {
            return;
        }
        match classify(entry) {
            Some(true) => push_unique(&mut self.v4, entry),
            Some(false) => push_unique(&mut self.v6, entry),
            None => push_unique(&mut self.unresolved_hosts, entry),
        }
    }
}

/// `Some(true)` = IPv4 literal/CIDR, `Some(false)` = IPv6, `None` = hostname.
fn classify(entry: &str) -> Option<bool> {
    let addr = entry.split('/').next().unwrap_or(entry);
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some(true),
        Ok(IpAddr::V6(_)) => Some(false),
        Err(_) => None,
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Build an `EgressPlan` from a policy's targets (IPs/CIDRs go straight in;
/// hostnames are surfaced in `unresolved_hosts` for the caller to resolve).
pub fn plan_from_policy(policy: &EngagementPolicy) -> EgressPlan {
    let mut plan = EgressPlan {
        program: policy.program.clone(),
        ..Default::default()
    };
    for t in &policy.targets {
        // "localhost" is the loopback, already allowed by the `lo` rule.
        if t.host.eq_ignore_ascii_case("localhost") {
            continue;
        }
        plan.add_destination(&t.host);
    }
    plan
}

/// Render the plan as an `nft -f` script: default-deny egress, allow loopback,
/// established/related, DNS, and the authorized destinations.
pub fn nftables_ruleset(plan: &EgressPlan) -> String {
    let mut s = String::new();
    s.push_str("#!/usr/sbin/nft -f\n");
    s.push_str(&format!(
        "# hiveCyber egress allowlist — generated from EngagementPolicy '{}'.\n",
        if plan.program.is_empty() { "(sin nombre)" } else { &plan.program }
    ));
    s.push_str("# Default-deny egress: solo se permite loopback, DNS, y los destinos autorizados.\n");
    if !plan.unresolved_hosts.is_empty() {
        s.push_str(&format!(
            "# AVISO: hostnames sin resolver (resuélvelos a IP y re-genera): {}\n",
            plan.unresolved_hosts.join(", ")
        ));
    }
    s.push_str("flush ruleset\n\n");
    s.push_str("table inet hivecyber_egress {\n");
    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority filter; policy drop;\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str("        ct state established,related accept\n");

    // DNS — needed to resolve target hostnames.
    if plan.resolvers.is_empty() {
        s.push_str("        udp dport 53 accept   # DNS (sin resolver fijo — considera restringirlo)\n");
        s.push_str("        tcp dport 53 accept\n");
    } else {
        let mut r4 = Vec::new();
        let mut r6 = Vec::new();
        for r in &plan.resolvers {
            match classify(r) {
                Some(true) => r4.push(r.clone()),
                Some(false) => r6.push(r.clone()),
                None => {}
            }
        }
        if !r4.is_empty() {
            let set = r4.join(", ");
            s.push_str(&format!("        ip daddr {{ {} }} udp dport 53 accept\n", set));
            s.push_str(&format!("        ip daddr {{ {} }} tcp dport 53 accept\n", set));
        }
        if !r6.is_empty() {
            let set = r6.join(", ");
            s.push_str(&format!("        ip6 daddr {{ {} }} udp dport 53 accept\n", set));
            s.push_str(&format!("        ip6 daddr {{ {} }} tcp dport 53 accept\n", set));
        }
    }

    if !plan.v4.is_empty() {
        s.push_str(&format!(
            "        ip daddr {{ {} }} accept   # targets autorizados (IPv4)\n",
            plan.v4.join(", ")
        ));
    }
    if !plan.v6.is_empty() {
        s.push_str(&format!(
            "        ip6 daddr {{ {} }} accept   # targets autorizados (IPv6)\n",
            plan.v6.join(", ")
        ));
    }

    s.push_str("        counter drop   # todo lo demás: bloqueado y contado\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement::TargetRule;

    fn policy_with(hosts: &[&str]) -> EngagementPolicy {
        EngagementPolicy {
            program: "acme-q3".into(),
            targets: hosts
                .iter()
                .map(|h| TargetRule {
                    host: h.to_string(),
                    paths: vec!["/**".into()],
                    methods: vec!["GET".into()],
                    rate_limit_rps: None,
                    only_own_accounts: false,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn classifies_ipv4_ipv6_and_hostnames() {
        let plan = plan_from_policy(&policy_with(&[
            "10.0.0.0/24",
            "203.0.113.5",
            "fe80::/10",
            "app.example.com",
            "localhost",
        ]));
        assert!(plan.v4.contains(&"10.0.0.0/24".to_string()));
        assert!(plan.v4.contains(&"203.0.113.5".to_string()));
        assert!(plan.v6.contains(&"fe80::/10".to_string()));
        assert!(plan.unresolved_hosts.contains(&"app.example.com".to_string()));
        // localhost is covered by the loopback rule, not an allowlist entry.
        assert!(!plan.unresolved_hosts.contains(&"localhost".to_string()));
    }

    #[test]
    fn ruleset_is_default_deny_and_allows_targets() {
        let mut plan = plan_from_policy(&policy_with(&["10.0.0.0/24"]));
        plan.resolvers.push("1.1.1.1".into());
        let nft = nftables_ruleset(&plan);
        assert!(nft.contains("policy drop;"), "must default-deny egress");
        assert!(nft.contains("oifname \"lo\" accept"));
        assert!(nft.contains("ip daddr { 10.0.0.0/24 } accept"), "target allowed");
        assert!(nft.contains("1.1.1.1") && nft.contains("dport 53"), "DNS to resolver allowed");
        assert!(nft.contains("counter drop"));
        // A non-target address must NOT appear as an allow rule.
        assert!(!nft.contains("8.8.8.8"));
    }

    #[test]
    fn extra_allow_infra_hosts() {
        // Simulate adding the LLM provider IP via --allow.
        let mut plan = plan_from_policy(&policy_with(&["10.0.0.5"]));
        plan.add_destination("104.18.0.0/16"); // e.g. LLM provider CIDR
        let nft = nftables_ruleset(&plan);
        assert!(nft.contains("10.0.0.5"));
        assert!(nft.contains("104.18.0.0/16"));
    }
}

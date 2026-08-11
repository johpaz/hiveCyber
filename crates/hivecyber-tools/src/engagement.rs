use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngagementPolicy {
    #[serde(default)]
    pub program: String,
    #[serde(default)]
    pub targets: Vec<TargetRule>,
    #[serde(default)]
    pub excluded: Vec<String>,
    #[serde(default)]
    pub prohibited: Vec<ProhibitedActivity>,
    #[serde(default)]
    pub require_human_approval: Vec<ApprovalCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_windows: Option<TimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetRule {
    pub host: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<f64>,
    #[serde(default)]
    pub only_own_accounts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitedActivity {
    DenialOfService,
    CredentialStuffing,
    SocialEngineering,
    AutomatedScanning,
    DataAccess,
    DestructiveTest,
    SocialMediaContact,
    PhysicalTesting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalCategory {
    Exploit,
    DataAccess,
    DestructiveTest,
    CredentialUse,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeWindow {
    #[serde(default)]
    pub allowed_days: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hours_utc: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct MatchOutcome<'a> {
    pub rule: Option<&'a TargetRule>,
    pub excluded: bool,
}

impl EngagementPolicy {
    pub fn empty() -> Self {
        EngagementPolicy::default()
    }

    /// Derive an `EngagementPolicy` from the legacy plain allowlist format
    /// (one host or CIDR per line). Each host becomes a permissive `TargetRule`
    /// — any path, any method, no rate limit.
    pub fn from_allowlist_hosts(hosts: &[String]) -> Self {
        let targets: Vec<TargetRule> = hosts
            .iter()
            .filter(|h| !h.is_empty())
            .map(|h| TargetRule {
                host: h.clone(),
                paths: vec!["/**".into()],
                methods: vec!["GET".into(), "POST".into()],
                rate_limit_rps: None,
                only_own_accounts: false,
            })
            .collect();
        EngagementPolicy {
            targets,
            ..Default::default()
        }
    }

    /// Whether `now` falls within the program's authorized operating window.
    /// No window configured → always allowed. `allowed_days` matches weekday
    /// names (case-insensitive, `Mon`/`Monday` both work); `allowed_hours_utc`
    /// is a `[start, end)` UTC hour range (wraps past midnight when start > end).
    pub fn is_within_window(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        use chrono::{Datelike, Timelike};
        let Some(tw) = &self.time_windows else {
            return true;
        };
        if !tw.allowed_days.is_empty() {
            let today = format!("{:?}", now.weekday()).to_lowercase(); // "mon", "tue", …
            let ok = tw.allowed_days.iter().any(|d| {
                let d = d.trim().to_lowercase();
                !d.is_empty() && (d.starts_with(&today) || today.starts_with(&d))
            });
            if !ok {
                return false;
            }
        }
        if let Some((start, end)) = tw.allowed_hours_utc {
            let h = now.hour();
            let in_hours = if start <= end {
                h >= start && h < end
            } else {
                h >= start || h < end
            };
            if !in_hours {
                return false;
            }
        }
        true
    }

    /// The rate limit (requests/sec) configured for the rule matching `target`,
    /// if any.
    pub fn rate_limit_for(&self, target: &str) -> Option<f64> {
        self.target_allowed(target).rule.and_then(|r| r.rate_limit_rps)
    }

    pub fn target_allowed(&self, raw_target: &str) -> MatchOutcome<'_> {
        let norm = normalize_host(raw_target);
        if norm.is_empty() {
            return MatchOutcome {
                rule: None,
                excluded: false,
            };
        }

        let excluded = self
            .excluded
            .iter()
            .any(|pattern| host_matches_pattern(&norm, pattern));

        let rule = self.targets.iter().find(|t| host_matches_rule(&norm, &t.host));

        MatchOutcome { rule, excluded }
    }

    pub fn request_allowed(&self, host: &str, path: &str, method: &str) -> Result<&TargetRule, String> {
        let outcome = self.target_allowed(host);
        if let Some(rule) = outcome.rule {
            if outcome.excluded {
                return Err(format!("target '{}' is excluded by policy", host));
            }
            if !rule.paths.is_empty()
                && !rule.paths.iter().any(|p| path_matches(p, path))
            {
                return Err(format!(
                    "path '{}' not allowed for host '{}' (permited: {:?})",
                    path, host, rule.paths
                ));
            }
            if !rule.methods.is_empty()
                && !rule
                    .methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method))
            {
                return Err(format!(
                    "method '{}' not allowed for host '{}' (allowed: {:?})",
                    method, host, rule.methods
                ));
            }
            Ok(rule)
        } else {
            Err(format!("host '{}' not in allowlist", host))
        }
    }

    pub fn is_prohibited(&self, activity: &ProhibitedActivity) -> bool {
        self.prohibited.iter().any(|a| a == activity)
    }

    pub fn requires_approval(&self, activity: &ApprovalCategory) -> bool {
        self.require_human_approval.iter().any(|a| a == activity)
    }
}

pub fn normalize_host(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return s;
    }
    // Strip IPv6 brackets
    if s.starts_with('[') && s.ends_with(']') {
        s = s[1..s.len() - 1].to_string();
    }
    // Strip scheme
    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        s = rest.to_string();
    }
    // Strip userinfo
    if let Some(idx) = s.find('@') {
        s = s[idx + 1..].to_string();
    }
    // Strip path/query/fragment
    for sep in ['/', '?', '#'] {
        if let Some(idx) = s.find(sep) {
            s = s[..idx].to_string();
        }
    }
    // Strip port. For IPv6 (which contains multiple ':') we cannot use rfind
    // naively — the IPv6 brackets were already stripped above, so a bare IPv6
    // literal like "fe80::1" must be preserved verbatim.
    if !s.contains('@') && s.matches(':').count() == 1 {
        if let Some(idx) = s.rfind(':') {
            let after = &s[idx + 1..];
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                s = s[..idx].to_string();
            }
        }
    }
    // Strip trailing dot
    while s.ends_with('.') {
        s.pop();
    }
    // Lowercase
    let s = s.to_lowercase();

    // Numeric/hex IPv4 forms
    if let Some(ip) = decode_numeric_ipv4(&s) {
        return ip;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return ip.to_string();
    }
    s
}

fn decode_numeric_ipv4(s: &str) -> Option<String> {
    // hex
    if s.starts_with("0x") || s.starts_with("0X") {
        if let Ok(n) = u32::from_str_radix(&s[2..], 16) {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(n)).to_string());
        }
    }
    // decimal (single integer in 0..2^32)
    if let Ok(n) = s.parse::<u64>() {
        if n <= u32::MAX as u64 {
            return Some(IpAddr::V4(std::net::Ipv4Addr::from(n as u32)).to_string());
        }
    }
    // octal dotted form e.g. 0177.0.0.1 — skip, rare enough.
    None
}

fn host_matches_rule(norm_host: &str, rule_host: &str) -> bool {
    let rule_host = rule_host.trim();
    if rule_host.is_empty() {
        return false;
    }
    // CIDR: split on '/' BEFORE normalizing. normalize_host treats '/' as a
    // path separator and strips everything after it (it exists to turn a
    // URL into a bare host) — calling it on "10.0.0.0/24" first would eat
    // the mask and silently turn every CIDR rule into a no-op exact-IP
    // check that could never match.
    if let Some((net_str, bits_str)) = rule_host.split_once('/') {
        let net_norm = normalize_host(net_str);
        if let (Ok(net), Ok(bits)) = (net_norm.parse::<IpAddr>(), bits_str.parse::<u32>()) {
            if let Ok(ip) = norm_host.parse::<IpAddr>() {
                return ip_in_cidr(ip, net, bits);
            }
        }
        return false;
    }
    let rule_norm = normalize_host(rule_host);
    if rule_norm.is_empty() {
        return false;
    }
    if let (Ok(a), Ok(b)) = (norm_host.parse::<IpAddr>(), rule_norm.parse::<IpAddr>()) {
        return a == b;
    }
    // exact or safe suffix (no `evil-example.com` matching `example.com`)
    norm_host == rule_norm || norm_host.ends_with(&format!(".{}", rule_norm))
}

fn host_matches_pattern(norm_host: &str, pattern: &str) -> bool {
    // Same CIDR-before-normalize handling as host_matches_rule — an
    // excluded entry is just a rule host matched the same way.
    host_matches_rule(norm_host, pattern)
}

fn ip_in_cidr(ip: IpAddr, prefix: IpAddr, mask_len: u32) -> bool {
    let max_bits = match (&ip, &prefix) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 32,
        (IpAddr::V6(_), IpAddr::V6(_)) => 128,
        _ => return false,
    };
    if mask_len > max_bits {
        return false;
    }
    match (ip, prefix, max_bits) {
        (IpAddr::V4(ip4), IpAddr::V4(net4), 32) => {
            let ip_int = u32::from(ip4);
            let net_int = u32::from(net4);
            let mask = if mask_len == 0 { 0 } else { !0u32 << (32 - mask_len) };
            (ip_int & mask) == net_int
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6), 128) => {
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

fn path_matches(pattern: &str, path: &str) -> bool {
    let p = pattern.trim_start_matches('/');
    let t = path.trim_start_matches('/');
    glob_match(p, t)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, 0, &t, 0)
}

fn glob_rec(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    // collapse `**` to a single `*` for matching purposes
    while pi < p.len() && p[pi] == '*' && pi + 1 < p.len() && p[pi + 1] == '*' {
        pi += 1;
    }
    if pi == p.len() {
        return ti == t.len();
    }
    if p[pi] == '*' {
        // try zero, one, or more chars
        for skip in 0..=(t.len() - ti) {
            if glob_rec(p, pi + 1, t, ti + skip) {
                return true;
            }
        }
        return false;
    }
    if ti == t.len() {
        return false;
    }
    if p[pi] == '?' || p[pi] == t[ti] {
        return glob_rec(p, pi + 1, t, ti + 1);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- normalize_host -----------------------------------------------------

    #[test]
    fn normalize_host_strips_scheme_userinfo_path_and_port() {
        assert_eq!(normalize_host("https://user:pass@Example.COM:8443/a/b?x=1#f"), "example.com");
        assert_eq!(normalize_host("http://example.com"), "example.com");
        assert_eq!(normalize_host("example.com:80"), "example.com");
    }

    #[test]
    fn normalize_host_preserves_ipv6_and_strips_brackets() {
        assert_eq!(normalize_host("[fe80::1]"), "fe80::1");
        assert_eq!(normalize_host("fe80::1"), "fe80::1");
    }

    #[test]
    fn normalize_host_strips_trailing_dot_and_lowercases() {
        assert_eq!(normalize_host("Example.COM."), "example.com");
    }

    #[test]
    fn normalize_host_decodes_numeric_ipv4() {
        // decimal
        assert_eq!(normalize_host("3232235521"), "192.168.0.1");
        // hex
        assert_eq!(normalize_host("0xC0A80001"), "192.168.0.1");
    }

    #[test]
    fn normalize_host_canonicalizes_dotted_ipv4() {
        assert_eq!(normalize_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn normalize_host_empty_stays_empty() {
        assert_eq!(normalize_host("   "), "");
    }

    // -- host_matches_rule (via target_allowed) ------------------------------

    #[test]
    fn target_allowed_matches_exact_host() {
        let policy = EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        assert!(policy.target_allowed("example.com").rule.is_some());
        assert!(policy.target_allowed("https://example.com/path").rule.is_some());
    }

    #[test]
    fn target_allowed_matches_subdomain_but_not_lookalike() {
        let policy = EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        assert!(policy.target_allowed("api.example.com").rule.is_some());
        // "evil-example.com" must NOT match an "example.com" allowlist entry —
        // this is a suffix match, not a substring match.
        assert!(policy.target_allowed("evil-example.com").rule.is_none());
        assert!(policy.target_allowed("notexample.com").rule.is_none());
    }

    #[test]
    fn target_allowed_matches_cidr_v4() {
        let policy = EngagementPolicy {
            targets: vec![TargetRule {
                host: "10.0.0.0/24".into(),
                paths: vec!["/**".into()],
                methods: vec![],
                rate_limit_rps: None,
                only_own_accounts: false,
            }],
            ..Default::default()
        };
        assert!(policy.target_allowed("10.0.0.5").rule.is_some());
        assert!(policy.target_allowed("10.0.1.5").rule.is_none());
    }

    #[test]
    fn target_allowed_matches_cidr_v6() {
        let policy = EngagementPolicy {
            targets: vec![TargetRule {
                host: "fe80::/64".into(),
                paths: vec![],
                methods: vec![],
                rate_limit_rps: None,
                only_own_accounts: false,
            }],
            ..Default::default()
        };
        assert!(policy.target_allowed("fe80::1").rule.is_some());
        assert!(policy.target_allowed("fe81::1").rule.is_none());
    }

    #[test]
    fn target_allowed_respects_exclusions() {
        let mut policy = EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        policy.excluded = vec!["admin.example.com".into()];
        assert!(!policy.target_allowed("example.com").excluded);
        assert!(policy.target_allowed("admin.example.com").excluded);
    }

    #[test]
    fn target_allowed_empty_policy_matches_nothing() {
        let policy = EngagementPolicy::empty();
        assert!(policy.target_allowed("example.com").rule.is_none());
    }

    // -- time windows ---------------------------------------------------------

    #[test]
    fn time_window_none_always_allows() {
        let policy = EngagementPolicy::default();
        let t = chrono::DateTime::parse_from_rfc3339("2026-01-05T14:00:00Z").unwrap().to_utc();
        assert!(policy.is_within_window(t));
    }

    #[test]
    fn time_window_enforces_hours_and_days() {
        // 2026-01-05 is a Monday.
        let monday_14 = chrono::DateTime::parse_from_rfc3339("2026-01-05T14:00:00Z").unwrap().to_utc();
        let monday_20 = chrono::DateTime::parse_from_rfc3339("2026-01-05T20:00:00Z").unwrap().to_utc();
        let sunday_14 = chrono::DateTime::parse_from_rfc3339("2026-01-04T14:00:00Z").unwrap().to_utc();

        let policy = EngagementPolicy {
            time_windows: Some(TimeWindow {
                allowed_days: vec!["Mon".into(), "Tue".into()],
                allowed_hours_utc: Some((9, 17)),
            }),
            ..Default::default()
        };
        assert!(policy.is_within_window(monday_14), "Mon 14:00 in [9,17) is allowed");
        assert!(!policy.is_within_window(monday_20), "Mon 20:00 outside hours");
        assert!(!policy.is_within_window(sunday_14), "Sunday not in allowed days");
    }

    #[test]
    fn time_window_hours_wrap_past_midnight() {
        // Overnight window 22:00–06:00 (start > end).
        let policy = EngagementPolicy {
            time_windows: Some(TimeWindow { allowed_days: vec![], allowed_hours_utc: Some((22, 6)) }),
            ..Default::default()
        };
        let t23 = chrono::DateTime::parse_from_rfc3339("2026-01-05T23:00:00Z").unwrap().to_utc();
        let t03 = chrono::DateTime::parse_from_rfc3339("2026-01-05T03:00:00Z").unwrap().to_utc();
        let t12 = chrono::DateTime::parse_from_rfc3339("2026-01-05T12:00:00Z").unwrap().to_utc();
        assert!(policy.is_within_window(t23));
        assert!(policy.is_within_window(t03));
        assert!(!policy.is_within_window(t12));
    }

    #[test]
    fn rate_limit_for_returns_rule_value() {
        let policy = EngagementPolicy {
            targets: vec![TargetRule {
                host: "example.com".into(),
                paths: vec!["/**".into()],
                methods: vec!["GET".into()],
                rate_limit_rps: Some(5.0),
                only_own_accounts: false,
            }],
            ..Default::default()
        };
        assert_eq!(policy.rate_limit_for("example.com"), Some(5.0));
        assert_eq!(policy.rate_limit_for("other.com"), None);
    }

    // -- request_allowed ------------------------------------------------------

    #[test]
    fn request_allowed_enforces_path_and_method() {
        let policy = EngagementPolicy {
            targets: vec![TargetRule {
                host: "example.com".into(),
                paths: vec!["/api/**".into()],
                methods: vec!["GET".into()],
                rate_limit_rps: None,
                only_own_accounts: false,
            }],
            ..Default::default()
        };
        assert!(policy.request_allowed("example.com", "/api/users", "GET").is_ok());
        assert!(policy.request_allowed("example.com", "/api/users", "get").is_ok()); // case-insensitive method
        assert!(policy.request_allowed("example.com", "/admin", "GET").is_err());
        assert!(policy.request_allowed("example.com", "/api/users", "DELETE").is_err());
    }

    #[test]
    fn request_allowed_rejects_excluded_target() {
        let mut policy = EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        policy.excluded = vec!["example.com".into()];
        assert!(policy.request_allowed("example.com", "/", "GET").is_err());
    }

    #[test]
    fn request_allowed_rejects_host_not_in_allowlist() {
        let policy = EngagementPolicy::from_allowlist_hosts(&["example.com".into()]);
        assert!(policy.request_allowed("other.com", "/", "GET").is_err());
    }

    // -- from_allowlist_hosts --------------------------------------------------

    #[test]
    fn from_allowlist_hosts_builds_permissive_rules() {
        let policy = EngagementPolicy::from_allowlist_hosts(&["a.com".into(), "".into(), "b.com".into()]);
        assert_eq!(policy.targets.len(), 2, "blank lines must be skipped");
        assert!(policy.targets.iter().all(|t| t.paths == vec!["/**".to_string()]));
    }

    // -- prohibited / approval categories --------------------------------------

    #[test]
    fn is_prohibited_and_requires_approval_check_membership() {
        let policy = EngagementPolicy {
            prohibited: vec![ProhibitedActivity::DenialOfService],
            require_human_approval: vec![ApprovalCategory::Exploit],
            ..Default::default()
        };
        assert!(policy.is_prohibited(&ProhibitedActivity::DenialOfService));
        assert!(!policy.is_prohibited(&ProhibitedActivity::DataAccess));
        assert!(policy.requires_approval(&ApprovalCategory::Exploit));
        assert!(!policy.requires_approval(&ApprovalCategory::CredentialUse));
    }

    // -- glob path matching -----------------------------------------------------

    #[test]
    fn path_matches_supports_wildcards() {
        assert!(path_matches("/api/**", "/api/v1/users"));
        assert!(path_matches("/api/*", "/api/users"));
        // This matcher has no `/`-boundary semantics — `*` and `**` both
        // match across path separators, so a single `*` also matches
        // multi-segment paths.
        assert!(path_matches("/api/*", "/api/v1/users"));
        assert!(path_matches("/*.txt", "/report.txt"));
        assert!(!path_matches("/*.txt", "/report.csv"));
    }
}
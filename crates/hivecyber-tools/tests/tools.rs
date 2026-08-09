use hivecyber_tools::{ToolRegistry, SecurityContext, Tool};
use std::sync::Arc;

#[tokio::test]
async fn test_registry_create_all_has_base_tools() {
    let reg = ToolRegistry::create_all();
    let names = reg.names();
    for expected in &[
        "fs_read", "fs_write", "fs_edit", "fs_glob", "fs_exists",
        "web_fetch", "cli_exec",
        "nmap", "dig", "whois", "theharvester",
        "nuclei", "nikto", "sqlmap", "searchsploit", "semgrep", "trivy",
        "metasploit_rpc", "hydra", "crackmapexec", "mimikatz",
        "volatility", "yara_scan", "zeek_parse", "osquery", "log_parse",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "tool '{}' should be registered",
            expected
        );
    }
}

#[tokio::test]
async fn test_registry_with_security_includes_all() {
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec);
    assert!(reg.names().len() >= 26, "expected 26+ tools with security");
}

#[tokio::test]
async fn test_fs_read_reads_file() {
    let reg = ToolRegistry::create_all();
    let tool = reg.get("fs_read").unwrap().clone();

    let result = tool
        .execute(serde_json::json!({
            "path": "/etc/hostname"
        }))
        .await
        .unwrap();
    assert!(result.get("content").is_some());
    assert!(result.get("total_lines").is_some());
}

#[tokio::test]
async fn test_fs_exists_checks_file() {
    let reg = ToolRegistry::create_all();
    let tool = reg.get("fs_exists").unwrap().clone();

    let result = tool
        .execute(serde_json::json!({"path": "/etc/hostname"}))
        .await
        .unwrap();
    assert_eq!(result.get("exists").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn test_fs_exists_nonexistent() {
    let reg = ToolRegistry::create_all();
    let tool = reg.get("fs_exists").unwrap().clone();

    let result = tool
        .execute(serde_json::json!({"path": "/tmp/this_does_not_exist_xyz_123"}))
        .await
        .unwrap();
    assert_eq!(result.get("exists").and_then(|v| v.as_bool()), Some(false));
}

#[tokio::test]
async fn test_fs_write_and_read_roundtrip() {
    let reg = ToolRegistry::create_all();
    let path = "/tmp/hc_test_roundtrip.txt";

    let write_tool = reg.get("fs_write").unwrap().clone();
    write_tool
        .execute(serde_json::json!({
            "path": path,
            "content": "hello hivecyber"
        }))
        .await
        .unwrap();

    let read_tool = reg.get("fs_read").unwrap().clone();
    let result = read_tool
        .execute(serde_json::json!({"path": path}))
        .await
        .unwrap();
    assert_eq!(
        result.get("content").and_then(|v| v.as_str()),
        Some("hello hivecyber")
    );

    let _ = tokio::fs::remove_file(path).await;
}

#[tokio::test]
async fn test_fs_edit_replaces_text() {
    let reg = ToolRegistry::create_all();
    let path = "/tmp/hc_test_edit.txt";

    let write = reg.get("fs_write").unwrap().clone();
    write
        .execute(serde_json::json!({
            "path": path,
            "content": "line one\nline two\nline three\n"
        }))
        .await
        .unwrap();

    let edit = reg.get("fs_edit").unwrap().clone();
    let result = edit
        .execute(serde_json::json!({
            "path": path,
            "old": "line two",
            "new": "LINE TWO EDITED"
        }))
        .await
        .unwrap();
    assert_eq!(result.get("replaced").and_then(|v| v.as_u64()), Some(1));

    let read = reg.get("fs_read").unwrap().clone();
    let content = read
        .execute(serde_json::json!({"path": path}))
        .await
        .unwrap();
    assert!(
        content
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("LINE TWO EDITED")
    );

    let _ = tokio::fs::remove_file(path).await;
}

#[tokio::test]
async fn test_cli_exec_dangerous_blocked() {
    let sec = Arc::new(SecurityContext {
        unsafe_mode: false,
        allowlist_hosts: vec![],
        operator_id: "test".into(),
    });
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "rm -rf /"
        }))
        .await;
    assert!(result.is_err(), "rm -rf / should be blocked");
}

#[tokio::test]
async fn test_cli_exec_sudo_blocked() {
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "sudo cat /etc/shadow"
        }))
        .await;
    assert!(result.is_err(), "sudo should be blocked");
}

#[tokio::test]
async fn test_cli_exec_hydra_blocked_without_unsafe() {
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "hydra -L users.txt -P pass.txt 10.0.0.5 ssh"
        }))
        .await;
    assert!(result.is_err(), "hydra should be blocked without --unsafe");
}

#[tokio::test]
async fn test_cli_exec_hydra_unsafe_but_no_allowlist() {
    let sec = Arc::new(SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec![],
        operator_id: "test".into(),
    });
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "hydra -L users.txt -P pass.txt 10.0.0.5 ssh"
        }))
        .await;
    assert!(
        result.is_err(),
        "hydra should be blocked even with --unsafe if allowlist is empty"
    );
}

#[tokio::test]
async fn test_cli_exec_hydra_allowed_with_unsafe_and_allowlist() {
    let sec = Arc::new(SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["10.0.0.0/24".into()],
        operator_id: "test".into(),
    });
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "echo 'hydra would run here'"
        }))
        .await;
    assert!(result.is_ok(), "safe echo should pass with unsafe+allowlist");
}

#[tokio::test]
async fn test_cli_exec_safe_command_works() {
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec);
    let cli = reg.get("cli_exec").unwrap().clone();

    let result = cli
        .execute(serde_json::json!({
            "command": "echo hello_hivecyber"
        }))
        .await
        .unwrap();
    assert_eq!(result.get("exit_code").and_then(|v| v.as_i64()), Some(0));
    assert!(
        result
            .get("stdout")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("hello_hivecyber")
    );
}

#[test]
fn test_filter_by_allowlist_exact() {
    let reg = ToolRegistry::create_all();
    let names = reg.filter_by_allowlist(&["nmap".into(), "dig".into()]);
    assert!(names.contains(&"nmap".to_string()));
    assert!(names.contains(&"dig".to_string()));
}

#[test]
fn test_filter_by_allowlist_glob() {
    let reg = ToolRegistry::create_all();
    let names = reg.filter_by_allowlist(&["fs_*".into()]);
    assert!(names.contains(&"fs_read".to_string()));
    assert!(names.contains(&"fs_write".to_string()));
    assert!(names.contains(&"fs_edit".to_string()));
    assert!(names.contains(&"fs_glob".to_string()));
    assert!(names.contains(&"fs_exists".to_string()));
}

#[test]
fn test_filter_by_allowlist_nonexistent() {
    let reg = ToolRegistry::create_all();
    let names = reg.filter_by_allowlist(&["nonexistent_tool".into()]);
    assert!(names.is_empty());
}

#[test]
fn test_security_context_validate_target_blocks_without_unsafe() {
    let sec = SecurityContext::default();
    let result = sec.validate_target("10.0.0.5");
    assert!(result.is_err());
}

#[test]
fn test_security_context_validate_target_blocks_without_allowlist() {
    let sec = SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec![],
        operator_id: "test".into(),
    };
    let result = sec.validate_target("10.0.0.5");
    assert!(result.is_err(), "should fail with empty allowlist");
}

#[test]
fn test_security_context_validate_target_allows_in_cidr() {
    let sec = SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["10.0.0.0/24".into()],
        operator_id: "test".into(),
    };
    assert!(sec.validate_target("10.0.0.5").is_ok());
    assert!(sec.validate_target("10.0.0.255").is_ok());
}

#[test]
fn test_security_context_validate_target_blocks_outside_cidr() {
    let sec = SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["10.0.0.0/24".into()],
        operator_id: "test".into(),
    };
    assert!(sec.validate_target("10.0.1.5").is_err());
    assert!(sec.validate_target("192.168.1.1").is_err());
}

#[test]
fn test_security_context_validate_target_allows_exact() {
    let sec = SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["example.com".into()],
        operator_id: "test".into(),
    };
    assert!(sec.validate_target("example.com").is_ok());
    assert!(sec.validate_target("evil.com").is_err());
}

#[test]
fn test_security_context_validate_ipv6_cidr() {
    let sec = SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["fe80::/10".into()],
        operator_id: "test".into(),
    };
    assert!(sec.validate_target("fe80::1").is_ok());
    assert!(sec.validate_target("2001:db8::1").is_err());
}
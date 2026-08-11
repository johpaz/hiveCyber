use hivecyber_core::store::HiveDb;
use hivecyber_core::store::collections::*;
use hivecyber_core::agent::catalog;
use hivecyber_core::agent::stuck::StuckLoopDetector;
use hivecyber_core::agent::acceptance::{run_acceptance_checks, verdict, CheckStatus};
use hivecyber_core::security::{policies, audit};
use std::path::PathBuf;
use std::sync::Arc;

async fn temp_db() -> HiveDb {
    let dir = PathBuf::from(format!("/tmp/hc_test_db_{}", uuid::Uuid::new_v4()));
    HiveDb::open(&dir).await.unwrap()
}

#[tokio::test]
async fn test_hivedb_insert_and_get() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "test_agent", serde_json::json!({"name": "Test"}))
        .await
        .unwrap();

    let val = db.get(COL_AGENTS, "test_agent").await;
    assert!(val.is_some());
    assert_eq!(
        val.unwrap().get("name").and_then(|v| v.as_str()),
        Some("Test")
    );
}

#[tokio::test]
async fn test_hivedb_delete() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "del_agent", serde_json::json!({"name": "Delete"}))
        .await
        .unwrap();
    assert!(db.get(COL_AGENTS, "del_agent").await.is_some());

    db.delete(COL_AGENTS, "del_agent").await.unwrap();
    assert!(db.get(COL_AGENTS, "del_agent").await.is_none());
}

#[tokio::test]
async fn test_hivedb_list() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "a1", serde_json::json!({"name": "A1"}))
        .await
        .unwrap();
    db.insert(COL_AGENTS, "a2", serde_json::json!({"name": "A2"}))
        .await
        .unwrap();

    let list = db.list(COL_AGENTS).await;
    assert_eq!(list.len(), 2);
}

#[tokio::test]
async fn test_hivedb_count() {
    let db = temp_db().await;

    assert_eq!(db.count(COL_AGENTS).await, 0);

    db.insert(COL_AGENTS, "x1", serde_json::json!({"name": "X1"}))
        .await
        .unwrap();
    assert_eq!(db.count(COL_AGENTS).await, 1);

    db.insert(COL_AGENTS, "x2", serde_json::json!({"name": "X2"}))
        .await
        .unwrap();
    assert_eq!(db.count(COL_AGENTS).await, 2);
}

#[tokio::test]
async fn test_hivedb_overwrite() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "ov", serde_json::json!({"version": 1}))
        .await
        .unwrap();
    db.insert(COL_AGENTS, "ov", serde_json::json!({"version": 2}))
        .await
        .unwrap();

    let val = db.get(COL_AGENTS, "ov").await.unwrap();
    assert_eq!(val.get("version").and_then(|v| v.as_u64()), Some(2));
}

#[test]
fn test_catalog_has_8_workers() {
    let personas = catalog::catalog_personas();
    assert_eq!(personas.len(), 8, "expected 8 catalog workers");
}

#[test]
fn test_catalog_has_recon_operator() {
    let personas = catalog::catalog_personas();
    let recon = personas.iter().find(|p| p.id == "recon_operator");
    assert!(recon.is_some());
    let recon = recon.unwrap();
    assert!(recon.tool_allowlist.contains(&"nmap".to_string()));
    assert!(recon.tool_allowlist.contains(&"dig".to_string()));
}

#[test]
fn test_catalog_has_exploit_operator() {
    let personas = catalog::catalog_personas();
    let exploit = personas.iter().find(|p| p.id == "exploit_operator");
    assert!(exploit.is_some());
    let exploit = exploit.unwrap();
    assert!(exploit.tool_allowlist.contains(&"metasploit_rpc".to_string()));
    assert!(exploit.tool_allowlist.contains(&"hydra".to_string()));
    assert!(exploit.model_override.is_some());
}

#[test]
fn test_catalog_has_all_8_ids() {
    let personas = catalog::catalog_personas();
    let ids: Vec<&str> = personas.iter().map(|p| p.id.as_str()).collect();
    for expected in &[
        "recon_operator",
        "vuln_scanner",
        "exploit_operator",
        "forensics_analyst",
        "web_pentester",
        "threat_intel_analyst",
        "report_writer",
        "workspace_file_operator",
    ] {
        assert!(
            ids.contains(expected),
            "catalog missing worker '{}'",
            expected
        );
    }
}

#[test]
fn test_catalog_coordinator_prompt_exists() {
    let prompt = catalog::COORDINATOR_SYSTEM_PROMPT;
    assert!(prompt.contains("Caelum"));
    assert!(prompt.contains("coordinador"));
}

#[test]
fn test_stuck_loop_detects_repeat() {
    let mut detector = StuckLoopDetector::new();
    assert!(detector.record_tool_call("nmap").is_none());
    assert!(detector.record_tool_call("nmap").is_none());
    assert!(detector.record_tool_call("nmap").is_none());
    let intervention = detector.record_tool_call("nmap");
    assert!(intervention.is_some(), "should detect 4-repeat stuck loop");
}

#[test]
fn test_stuck_loop_resets_on_different_tool() {
    let mut detector = StuckLoopDetector::new();
    detector.record_tool_call("nmap");
    detector.record_tool_call("nmap");
    detector.record_tool_call("dig");
    assert!(detector.record_tool_call("dig").is_none());
    assert!(detector.record_tool_call("dig").is_none());
    let intervention = detector.record_tool_call("dig");
    assert!(intervention.is_some());
}

#[test]
fn test_stuck_loop_idle_detection() {
    let mut detector = StuckLoopDetector::new();
    assert!(detector.record_idle().is_none());
    assert!(detector.record_idle().is_none());
    assert!(detector.record_idle().is_some(), "should detect 3-idle");
}

#[test]
fn test_acceptance_empty_delivery_fails() {
    let acceptance = vec![];
    let checks = run_acceptance_checks("test", &acceptance, "", &[]);
    assert!(!checks.is_empty());
    assert_eq!(verdict(&checks), CheckStatus::Failed);
}

#[test]
fn test_acceptance_self_declared_failure() {
    let acceptance = vec![AcceptanceCriterion {
        id: "obj".into(),
        description: "do the thing".into(),
        check_tool: None,
    }];
    let checks = run_acceptance_checks(
        "do the thing",
        &acceptance,
        "status: failed\nwhat_was_done: nothing",
        &[],
    );
    assert_eq!(verdict(&checks), CheckStatus::Failed);
}

#[test]
fn test_acceptance_no_checktool_is_pending() {
    let acceptance = vec![AcceptanceCriterion {
        id: "obj".into(),
        description: "deliver report".into(),
        check_tool: None,
    }];
    let checks = run_acceptance_checks(
        "deliver report",
        &acceptance,
        "status: completed\ndelivery text here",
        &[],
    );
    assert_eq!(verdict(&checks), CheckStatus::Pending);
}

#[test]
fn test_acceptance_unknown_checktool_is_pending() {
    let acceptance = vec![AcceptanceCriterion {
        id: "obj".into(),
        description: "custom".into(),
        check_tool: Some("custom_verifier_xyz".into()),
    }];
    let checks = run_acceptance_checks(
        "custom",
        &acceptance,
        "status: completed\ndelivery here",
        &[],
    );
    assert_eq!(verdict(&checks), CheckStatus::Pending);
}

#[test]
fn test_acceptance_recon_coverage_passes() {
    let acceptance = vec![AcceptanceCriterion {
        id: "recon_coverage".into(),
        description: "coverage".into(),
        check_tool: Some("recon_coverage".into()),
    }];
    let evidence = vec![
        "nmap: 10.0.0.5 open ports 22 80 443".into(),
        "dig: example.com A 10.0.0.5".into(),
    ];
    let checks = run_acceptance_checks("scan 10.0.0.5", &acceptance, "status: completed", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_recon_coverage_fails_sparse() {
    let acceptance = vec![AcceptanceCriterion {
        id: "recon_coverage".into(),
        description: "coverage".into(),
        check_tool: Some("recon_coverage".into()),
    }];
    let evidence = vec!["nmap: no output here".into()];
    let checks = run_acceptance_checks("scan", &acceptance, "status: completed", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Failed);
}

#[test]
fn test_acceptance_vuln_findings_passes_with_cve() {
    let acceptance = vec![AcceptanceCriterion {
        id: "vuln_findings".into(),
        description: "findings".into(),
        check_tool: Some("vuln_findings".into()),
    }];
    let evidence = vec!["nuclei: CVE-2021-44228 log4shell severity critical".into()];
    let checks = run_acceptance_checks("scan", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_exploit_proof_passes_with_session() {
    let acceptance = vec![AcceptanceCriterion {
        id: "exploit_proof".into(),
        description: "proof".into(),
        check_tool: Some("exploit_proof".into()),
    }];
    let evidence = vec!["metasploit_rpc: meterpreter session 1 opened".into()];
    let checks = run_acceptance_checks("exploit", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_forensics_evidence_passes() {
    let acceptance = vec![AcceptanceCriterion {
        id: "forensics_evidence".into(),
        description: "forensics".into(),
        check_tool: Some("forensics_evidence".into()),
    }];
    let evidence = vec![
        "volatility: sha256 6a1b31c4e5a8e8b3f2d4c5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6 acquired 2024-01-01T12:00:00Z".into(),
    ];
    let checks = run_acceptance_checks("forensics", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_intel_correlation_passes_two_sources() {
    let acceptance = vec![AcceptanceCriterion {
        id: "intel_correlation".into(),
        description: "correlation".into(),
        check_tool: Some("intel_correlation".into()),
    }];
    let evidence = vec![
        "shodan: 10.0.0.5 ports 80 443".into(),
        "whois: example.com".into(),
    ];
    let checks = run_acceptance_checks("intel", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_intel_correlation_fails_one_source() {
    let acceptance = vec![AcceptanceCriterion {
        id: "intel_correlation".into(),
        description: "correlation".into(),
        check_tool: Some("intel_correlation".into()),
    }];
    let evidence = vec!["shodan: 10.0.0.5".into()];
    let checks = run_acceptance_checks("intel", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Failed);
}

#[test]
fn test_acceptance_report_complete_passes() {
    let acceptance = vec![AcceptanceCriterion {
        id: "report_complete".into(),
        description: "report".into(),
        check_tool: Some("report_complete".into()),
    }];
    let delivery = "status: completed\nexec-summary: overview\nfindings: 3 issues\nremediation: patch now";
    let evidence = vec!["fs_write: report.md".into()];
    let checks = run_acceptance_checks("report", &acceptance, delivery, &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_readback_passes() {
    let acceptance = vec![AcceptanceCriterion {
        id: "readback".into(),
        description: "readback".into(),
        check_tool: Some("readback".into()),
    }];
    let evidence = vec![
        "fs_write: /tmp/out.txt hello".into(),
        "fs_read: /tmp/out.txt hello".into(),
    ];
    let checks = run_acceptance_checks("readback", &acceptance, "done", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed);
}

#[test]
fn test_acceptance_empty_acceptance_with_delivery_is_unchecked() {
    let acceptance: Vec<AcceptanceCriterion> = vec![];
    let checks = run_acceptance_checks("obj", &acceptance, "delivery text", &[]);
    assert_eq!(verdict(&checks), CheckStatus::Unchecked);
}

#[tokio::test]
async fn test_audit_log_chain_verifies_empty() {
    let db = temp_db().await;
    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "empty chain should verify: errors={:?}", errors);
}

#[tokio::test]
async fn test_audit_log_append_and_verify() {
    let db = temp_db().await;

    let prev_hash = audit::get_last_hash(&db).await;
    let h1 = audit::log_audit(&db, "nmap", "10.0.0.5", "recon_operator", "run_1", "operator_1", &prev_hash)
        .await
        .unwrap();
    let h2 = audit::log_audit(&db, "hydra", "10.0.0.5", "exploit_operator", "run_2", "operator_1", &h1)
        .await
        .unwrap();
    let _ = audit::log_audit(&db, "mimikatz", "localhost", "exploit_operator", "run_3", "operator_1", &h2)
        .await
        .unwrap();

    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "chain should verify: errors={:?}", errors);

    let entries = db.list(COL_AUDIT_LOG).await;
    assert_eq!(entries.len(), 3);
}

#[tokio::test]
async fn test_audit_chain_holds_with_get_last_hash_pattern() {
    // Regression for the real bug the E2E exposed: the middleware reads the
    // previous hash with `get_last_hash` on every call (it does NOT thread the
    // returned hash). `db.list` sorts by UUID, not by time, so once 3+ entries
    // exist and the random UUIDs stop sorting in insertion order, `.last()`
    // returned the wrong "prev" and the chain broke on `verify`. Six entries
    // make the UUID/time divergence overwhelmingly likely (P(sorted)=1/720).
    let db = temp_db().await;

    for i in 0..6 {
        let prev = audit::get_last_hash(&db).await;
        audit::log_audit(
            &db,
            &format!("tool_{}", i),
            "10.0.0.5",
            "caelum",
            "run_x",
            "op1",
            &prev,
        )
        .await
        .unwrap();
    }

    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "chain must verify with the get_last_hash pattern: {:?}", errors);
    assert_eq!(db.list(COL_AUDIT_LOG).await.len(), 6);
}

#[tokio::test]
async fn test_policies_increment_harmful() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "test_worker", serde_json::json!({
        "id": "test_worker",
        "name": "Test",
        "enabled": true,
        "harmful_count": 0u32,
        "helpful_count": 0u32,
    }))
    .await
    .unwrap();

    policies::increment_harmful(&db, "test_worker").await.unwrap();
    let agent = db.get(COL_AGENTS, "test_worker").await.unwrap();
    assert_eq!(agent.get("harmful_count").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(
        agent.get("enabled").and_then(|v| v.as_bool()),
        Some(true),
        "1 harmful should not disable"
    );
}

#[tokio::test]
async fn test_policies_auto_pause_at_3() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "auto_pause", serde_json::json!({
        "id": "auto_pause",
        "name": "AutoPause",
        "enabled": true,
        "harmful_count": 2u32,
        "helpful_count": 0u32,
    }))
    .await
    .unwrap();

    policies::increment_harmful(&db, "auto_pause").await.unwrap();
    let agent = db.get(COL_AGENTS, "auto_pause").await.unwrap();
    assert_eq!(
        agent.get("enabled").and_then(|v| v.as_bool()),
        Some(false),
        "3 harmful > 0 helpful should auto-pause"
    );
}

#[tokio::test]
async fn test_policies_auto_disable_at_5() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "auto_disable", serde_json::json!({
        "id": "auto_disable",
        "name": "AutoDisable",
        "enabled": true,
        "harmful_count": 4u32,
        "helpful_count": 0u32,
    }))
    .await
    .unwrap();

    policies::increment_harmful(&db, "auto_disable").await.unwrap();
    let agent = db.get(COL_AGENTS, "auto_disable").await.unwrap();
    assert_eq!(agent.get("enabled").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        agent.get("status").and_then(|v| v.as_str()),
        Some("auto_disabled")
    );
}

#[tokio::test]
async fn test_policies_increment_helpful() {
    let db = temp_db().await;

    db.insert(COL_AGENTS, "good_worker", serde_json::json!({
        "id": "good_worker",
        "name": "Good",
        "enabled": true,
        "harmful_count": 0u32,
        "helpful_count": 0u32,
    }))
    .await
    .unwrap();

    for _ in 0..5 {
        policies::increment_helpful(&db, "good_worker").await.unwrap();
    }
    let agent = db.get(COL_AGENTS, "good_worker").await.unwrap();
    assert_eq!(agent.get("helpful_count").and_then(|v| v.as_u64()), Some(5));
    assert_eq!(agent.get("enabled").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn test_run_store_create_and_complete() {
    let db = temp_db().await;

    let run_id = hivecyber_core::agent::run_store::create_run(
        &db,
        "chat",
        "caelum",
        "thread_1",
        serde_json::json!({"text": "test"}),
    )
    .await
    .unwrap();

    let run = db.get(COL_RUNS, &run_id).await.unwrap();
    assert_eq!(run.get("status").and_then(|v| v.as_str()), Some("pending"));

    hivecyber_core::agent::run_store::complete_run(&db, &run_id)
        .await
        .unwrap();
    let run = db.get(COL_RUNS, &run_id).await.unwrap();
    assert_eq!(run.get("status").and_then(|v| v.as_str()), Some("completed"));
}

#[tokio::test]
async fn test_run_store_fail_run() {
    let db = temp_db().await;

    let run_id = hivecyber_core::agent::run_store::create_run(
        &db,
        "worker",
        "recon_operator",
        "thread_2",
        serde_json::json!({"text": "scan"}),
    )
    .await
    .unwrap();

    hivecyber_core::agent::run_store::fail_run(&db, &run_id, "timeout")
        .await
        .unwrap();
    let run = db.get(COL_RUNS, &run_id).await.unwrap();
    assert_eq!(run.get("status").and_then(|v| v.as_str()), Some("failed"));
}

#[tokio::test]
async fn test_durable_queue_enqueue_and_complete() {
    let db = temp_db().await;
    let queue = hivecyber_core::harness::DurableQueue::new(db.clone());

    let job_id = queue
        .enqueue("task:test_1", "worker_task", serde_json::json!({"taskId": "t1"}), None)
        .await
        .unwrap();

    let job = db.get(COL_JOBS, &job_id).await.unwrap();
    assert_eq!(job.get("status").and_then(|v| v.as_str()), Some("pending"));
    assert_eq!(job.get("lane").and_then(|v| v.as_str()), Some("task:test_1"));

    queue.claim_job(&job_id).await.unwrap();
    let job = db.get(COL_JOBS, &job_id).await.unwrap();
    assert_eq!(job.get("status").and_then(|v| v.as_str()), Some("running"));

    queue
        .complete_job(&job_id, serde_json::json!({"result": "ok"}))
        .await
        .unwrap();
    let job = db.get(COL_JOBS, &job_id).await.unwrap();
    assert_eq!(job.get("status").and_then(|v| v.as_str()), Some("completed"));
}

#[tokio::test]
async fn test_durable_queue_find_pending_by_lane() {
    let db = temp_db().await;
    let queue = hivecyber_core::harness::DurableQueue::new(db.clone());

    queue
        .enqueue("task:a", "worker_task", serde_json::json!({}), None)
        .await
        .unwrap();
    queue
        .enqueue("task:b", "worker_task", serde_json::json!({}), None)
        .await
        .unwrap();
    queue
        .enqueue("task:a", "worker_task", serde_json::json!({}), None)
        .await
        .unwrap();

    let pending_a = queue.find_pending_by_lane("task:a").await;
    assert_eq!(pending_a.len(), 2);

    let pending_b = queue.find_pending_by_lane("task:b").await;
    assert_eq!(pending_b.len(), 1);

    let pending_c = queue.find_pending_by_lane("task:c").await;
    assert_eq!(pending_c.len(), 0);
}

#[tokio::test]
async fn test_delegation_create_task() {
    let db = temp_db().await;

    let task_id = hivecyber_core::agent::delegation::create_task(
        &db,
        "recon_operator",
        "Scan 10.0.0.0/24",
        vec![AcceptanceCriterion {
            id: "recon_coverage".into(),
            description: "Coverage matches scope".into(),
            check_tool: Some("recon_coverage".into()),
        }],
        "turn_1",
    )
    .await
    .unwrap();

    let task = db.get(COL_TASKS, &task_id).await.unwrap();
    assert_eq!(task.get("status").and_then(|v| v.as_str()), Some("pending"));
    assert_eq!(
        task.get("worker_id").and_then(|v| v.as_str()),
        Some("recon_operator")
    );
    assert_eq!(
        task.get("delegation_group_id").and_then(|v| v.as_str()),
        Some("turn_1")
    );
}

#[tokio::test]
async fn test_middleware_audits_tool_execution() {
    use hivecyber_core::tool_runtime::middleware::{AuditCtx, ToolMiddleware};
    use hivecyber_tools::{SecurityContext, Tool, ToolRegistry};

    let db = temp_db().await;
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec.clone());
    let mw = ToolMiddleware::new(db.clone(), sec);

    let tool = reg.get("fs_read").unwrap().clone() as Arc<dyn Tool>;
    let ctx = AuditCtx {
        worker: "recon_operator".into(),
        run_id: "run_x".into(),
        operator_id: "operator_1".into(),
    };

    let args = serde_json::json!({"path": "/etc/hostname"});
    let result = mw.execute(tool, "fs_read", args, 30_000, &ctx).await;

    assert!(result.success, "fs_read should succeed on /etc/hostname");

    let entries = db.list(COL_AUDIT_LOG).await;
    assert_eq!(entries.len(), 1, "exactly one audit entry should exist");
    let entry = &entries[0].1;
    assert_eq!(entry.get("tool").and_then(|v| v.as_str()), Some("fs_read"));
    assert_eq!(entry.get("worker").and_then(|v| v.as_str()), Some("recon_operator"));
    assert_eq!(entry.get("run_id").and_then(|v| v.as_str()), Some("run_x"));

    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "audit chain should verify after one tool: {:?}", errors);
}

#[tokio::test]
async fn test_middleware_audits_every_call_in_batch() {
    use hivecyber_core::tool_runtime::middleware::{AuditCtx, ToolMiddleware};
    use hivecyber_core::tool_runtime::middleware::execute_tool_batch_audited;
    use hivecyber_tools::{SecurityContext, ToolRegistry};

    let db = temp_db().await;
    let sec = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec.clone());
    let mw = ToolMiddleware::new(db.clone(), sec);

    let ctx = AuditCtx {
        worker: "w1".into(),
        run_id: "r1".into(),
        operator_id: "op".into(),
    };

    let calls = vec![
        ("fs_exists".to_string(), serde_json::json!({"path": "/etc/hostname"})),
        ("fs_exists".to_string(), serde_json::json!({"path": "/nonexistent_xyz"})),
    ];
    let results = execute_tool_batch_audited(calls, &reg, 30_000, &mw, &ctx).await;

    let audit_entries = db.list(COL_AUDIT_LOG).await;
    assert_eq!(
        audit_entries.len(),
        results.len(),
        "one audit entry per tool call, regardless of success"
    );

    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "chain should verify: {:?}", errors);
}

#[test]
fn test_extract_target_handles_structured_tools() {
    use hivecyber_core::tool_runtime::middleware::extract_target;

    let nmap_args = serde_json::json!({"target": "10.0.0.5"});
    assert_eq!(extract_target("nmap", &nmap_args), Some("10.0.0.5".into()));

    let msf_args = serde_json::json!({"target": "10.0.0.5", "module": "auxiliary/scanner/smb/smb_version"});
    assert_eq!(extract_target("metasploit_rpc", &msf_args).as_deref(), Some("10.0.0.5"));

    let web = serde_json::json!({"url": "https://example.com/admin"});
    assert_eq!(extract_target("web_fetch", &web).as_deref(), Some("https://example.com/admin"));

    assert_eq!(extract_target("unknown_tool", &web), None);
}

// End-to-end: an Isolation::Sandbox tool routed through the middleware must
// actually reach the real `hivecyber-worker` binary (seccomp + rlimits +
// namespaces applied, not skipped), and the worker must enforce the
// *caller's* SecurityContext — not a fresh default one. A prior version of
// this routing silently rebuilt the worker's tool registry from
// SecurityContext::default() on every call, so every exploit tool always
// rejected itself with "unsafe_mode disabled" regardless of what the
// operator actually authorized. This test pins both behaviors down.
#[tokio::test]
async fn test_middleware_sandbox_roundtrip_enforces_caller_security_context() {
    use hivecyber_core::tool_runtime::middleware::{AuditCtx, ToolMiddleware};
    use hivecyber_tools::{SecurityContext, Tool, ToolRegistry};

    let worker_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/hivecyber-worker");
    assert!(
        worker_bin.exists(),
        "hivecyber-worker binary not built at {:?} — run `cargo build -p hivecyber-worker` first",
        worker_bin
    );
    // Safe here: no other test in this binary reads HIVECYBER_WORKER_BIN.
    std::env::set_var("HIVECYBER_WORKER_BIN", &worker_bin);

    let db = temp_db().await;
    let args = serde_json::json!({
        // No dots in these values: CliExec's out-of-scope heuristic treats
        // any dotted token as a host/IP that must be allowlisted, and would
        // reject a literal filename like "users.txt" for an unrelated
        // reason before we ever get to observe the security_policy check
        // this test is actually about.
        "target": "10.0.0.5", "service": "ssh", "users": "userlist", "passwords": "passlist"
    });

    // 1. unsafe_mode disabled — must be rejected *inside the worker process*.
    let sec_locked = Arc::new(SecurityContext::default());
    let reg = ToolRegistry::create_with_security(sec_locked.clone());
    let mw = ToolMiddleware::new(db.clone(), sec_locked);
    let tool = reg.get("hydra").unwrap().clone() as Arc<dyn Tool>;
    let ctx = AuditCtx { worker: "exploit_operator".into(), run_id: "run_sbx1".into(), operator_id: "op1".into() };

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        mw.execute(tool, "hydra", args.clone(), 15_000, &ctx),
    )
    .await
    .expect("sandboxed tool call must not hang");

    assert!(result.success, "worker round-trip should complete: {:?}", result.error);
    assert_eq!(
        result.result.get("error").and_then(|v| v.as_str()),
        Some("security_policy"),
        "unsafe_mode=false must be enforced inside the worker, not bypassed: {:?}",
        result.result
    );

    // 2. unsafe_mode enabled + target allowlisted — must get *past* the
    // security gate (it will still fail downstream since no real `hydra`
    // binary or credential files exist in the test environment; we only
    // assert it wasn't rejected by security policy).
    let sec_unlocked = Arc::new(SecurityContext {
        unsafe_mode: true,
        allowlist_hosts: vec!["10.0.0.5".into()],
        operator_id: "op1".into(),
        allow_cli_exec: true,
        ..SecurityContext::default()
    });
    let reg2 = ToolRegistry::create_with_security(sec_unlocked.clone());
    let mw2 = ToolMiddleware::new(db.clone(), sec_unlocked);
    let tool2 = reg2.get("hydra").unwrap().clone() as Arc<dyn Tool>;
    let ctx2 = AuditCtx { worker: "exploit_operator".into(), run_id: "run_sbx2".into(), operator_id: "op1".into() };

    let result2 = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        mw2.execute(tool2, "hydra", args, 15_000, &ctx2),
    )
    .await
    .expect("sandboxed tool call must not hang");

    assert!(result2.success, "worker round-trip should complete: {:?}", result2.error);
    assert_ne!(
        result2.result.get("error").and_then(|v| v.as_str()),
        Some("security_policy"),
        "with unsafe_mode + allowlist, the call must get past the security gate: {:?}",
        result2.result
    );

    // Both attempts — allowed and denied — must be audited.
    let entries = db.list(COL_AUDIT_LOG).await;
    assert_eq!(entries.len(), 2, "both sandboxed attempts must be audited");
}
// ---- Fase 5C: agent memory + task_list/task_revise ----

#[tokio::test]
async fn test_memory_write_read_list_search() {
    use hivecyber_core::agent::memory_backend::MemoryBackend;
    use hivecyber_tools::memory::MemoryBackend as _;

    let db = temp_db().await;
    let mem = MemoryBackend { db: db.clone() };

    // Write two notes in different namespaces.
    mem.write("recon", "host-a", "puerto 443 abierto, nginx 1.18", vec!["nginx".into(), "https".into()])
        .await
        .unwrap();
    mem.write("recon", "host-b", "puerto 22 abierto, openssh", vec!["ssh".into()])
        .await
        .unwrap();
    mem.write("notes", "todo", "revisar credenciales por defecto", vec![])
        .await
        .unwrap();

    // Read back exact.
    let a = mem.read("recon", "host-a").await.unwrap().expect("note exists");
    assert_eq!(a.get("content").and_then(|v| v.as_str()), Some("puerto 443 abierto, nginx 1.18"));

    // Missing read → None.
    assert!(mem.read("recon", "nope").await.unwrap().is_none());

    // List scoped by namespace.
    let recon = mem.list(Some("recon"), 10).await.unwrap();
    assert_eq!(recon.len(), 2, "two notes in recon ns");
    let all = mem.list(None, 10).await.unwrap();
    assert_eq!(all.len(), 3, "three notes total");

    // Search by keyword (only host-a mentions nginx).
    let hits = mem.search("nginx", None, 10).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].get("key").and_then(|v| v.as_str()), Some("host-a"));

    // Search scoped to a namespace that has no match.
    let none = mem.search("nginx", Some("notes"), 10).await.unwrap();
    assert!(none.is_empty());

    // Upsert keeps created_at but updates content.
    mem.write("recon", "host-a", "actualizado: TLS1.3", vec![]).await.unwrap();
    let again = mem.list(Some("recon"), 10).await.unwrap();
    assert_eq!(again.len(), 2, "upsert must not create a duplicate");
    let a2 = mem.read("recon", "host-a").await.unwrap().unwrap();
    assert_eq!(a2.get("content").and_then(|v| v.as_str()), Some("actualizado: TLS1.3"));
}

#[tokio::test]
async fn test_task_list_and_revise() {
    use hivecyber_core::agent::delegation_backend::TaskDelegateBackend;
    use hivecyber_core::harness::DurableQueue;
    use hivecyber_tools::delegation::TaskDelegateBackend as _;

    let db = temp_db().await;
    let queue = Arc::new(DurableQueue::new(db.clone()));
    let backend = TaskDelegateBackend { db: db.clone(), queue };

    // Delegate two tasks in the same turn/group.
    let (t1, _j1) = backend
        .create_task("recon_operator", "escanear host-a", vec![], "turn-1", "thread-1")
        .await
        .unwrap();
    let (_t2, _j2) = backend
        .create_task("report_writer", "redactar informe", vec![], "turn-1", "thread-1")
        .await
        .unwrap();

    // task_list returns both, most-recent first.
    let all = backend.list_tasks(None, 10).await.unwrap();
    assert_eq!(all.len(), 2);

    // Filter by status (both pending initially).
    let pending = backend.list_tasks(Some("pending".into()), 10).await.unwrap();
    assert_eq!(pending.len(), 2);
    let done = backend.list_tasks(Some("completed".into()), 10).await.unwrap();
    assert!(done.is_empty());

    // Revise t1 → re-queued, description carries the note, same worker.
    let res = backend.revise_task(&t1, "incluye escaneo UDP").await.unwrap();
    assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(res.get("worker_id").and_then(|v| v.as_str()), Some("recon_operator"));
    assert!(res.get("job_id").and_then(|v| v.as_str()).is_some());

    let t1_doc = db.get(COL_TASKS, &t1).await.unwrap();
    assert_eq!(t1_doc.get("status").and_then(|v| v.as_str()), Some("pending"));
    assert!(t1_doc
        .get("task_description")
        .and_then(|v| v.as_str())
        .unwrap()
        .contains("incluye escaneo UDP"));
    assert_eq!(t1_doc.get("revision_notes").and_then(|v| v.as_str()), Some("incluye escaneo UDP"));

    // Revising a missing task errors.
    assert!(backend.revise_task("does-not-exist", "x").await.is_err());
}

// ---- Fase 5A: MCP tool-proxy end-to-end (agent side, stdio) ----
//
// Proves the full agent-facing path: load a server from `mcp_servers`, connect
// it over stdio, register its tools into a real `ToolRegistry` via
// `register_mcp_tools`, and execute one through the proxy (proxy → manager →
// server). Gated on `python3` being available so it is a no-op where it isn't.

#[tokio::test]
async fn test_mcp_tool_proxy_registers_and_executes() {
    use std::io::Write;
    use std::sync::Arc;

    // Skip cleanly if python3 is unavailable (keeps CI portable).
    if std::process::Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 not found — skipping MCP proxy e2e");
        return;
    }

    // Minimal stdio MCP server: initialize, tools/list (add), tools/call.
    let script = r#"import sys, json
def send(o): sys.stdout.write(json.dumps(o)+"\n"); sys.stdout.flush()
TOOLS=[{"name":"add","description":"suma","inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}}]
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    r=json.loads(line); rid=r.get("id"); m=r.get("method")
    if rid is None: continue
    if m=="initialize": send({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t","version":"1"}}})
    elif m=="tools/list": send({"jsonrpc":"2.0","id":rid,"result":{"tools":TOOLS}})
    elif m=="tools/call":
        a=r["params"]["arguments"]; send({"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":str(a["a"]+a["b"])}]}})
    else: send({"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":"?"}})
"#;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(script.as_bytes()).unwrap();
    let path = f.path().to_string_lossy().to_string();

    let db = temp_db().await;
    // Register the server in the mcp_servers collection.
    db.insert(
        COL_MCP_SERVERS,
        "echo",
        serde_json::json!({
            "enabled": true,
            "transport": "stdio",
            "command": "python3",
            "args": [path],
        }),
    )
    .await
    .unwrap();

    // Load + connect from the store, then register the proxies into a registry.
    let mcp = hivecyber_core::agent::mcp_integration::load_and_connect(&db).await;
    let mut registry = hivecyber_tools::ToolRegistry::create_with_security(Arc::new(
        hivecyber_tools::SecurityContext::default(),
    ));
    let n = hivecyber_core::agent::mcp_integration::register_mcp_tools(&mut registry, &mcp).await;
    assert_eq!(n, 1, "one MCP tool should be registered");

    // The proxy is in the registry and executes through the server.
    let tool = registry.get("add").expect("add proxy registered");
    let out = tool
        .execute(serde_json::json!({"a": 2, "b": 40}))
        .await
        .unwrap();
    let text = out
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|o| o.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    assert_eq!(text, "42", "proxy → manager → mcp server round-trip");

    mcp.lock().await.disconnect_all().await;
}

// ---- Roadmap: catalog-selector + skill-selector wired via routing_context ----

#[tokio::test]
async fn test_routing_context_ranks_workers_and_skills() {
    use hivecyber_core::agent::routing_context::{build_coordinator_context, build_skill_context};

    let db = temp_db().await;

    // Two workers with routing_exclusions; report_writer excludes port scans.
    db.insert(COL_AGENTS, "recon_operator", serde_json::json!({
        "id": "recon_operator", "name": "Recon", "role": "worker", "enabled": true,
        "description": "Reconocimiento activo y OSINT con nmap y shodan.",
        "tool_allowlist_json": ["nmap", "shodan", "dig"],
        "skills_json": ["recon_workflow"],
        "routing_exclusions_json": ["redaccion de informes"],
    })).await.unwrap();
    db.insert(COL_AGENTS, "report_writer", serde_json::json!({
        "id": "report_writer", "name": "Reporter", "role": "worker", "enabled": true,
        "description": "Redacta informes de pentest en docx y pdf.",
        "tool_allowlist_json": ["office_write"],
        "skills_json": ["pentest_report"],
        "routing_exclusions_json": ["escaneo de puertos", "explotacion de vulnerabilidades"],
    })).await.unwrap();
    // A non-worker (coordinator) must be excluded from the roster.
    db.insert(COL_AGENTS, "caelum", serde_json::json!({
        "id": "caelum", "name": "Caelum", "role": "coordinator", "enabled": true,
        "description": "coordina",
    })).await.unwrap();

    // Skills in COL_SKILLS (as sync_skills_to_db would write them).
    db.insert(COL_SKILLS, "recon_workflow", serde_json::json!({
        "id": "recon_workflow", "name": "recon_workflow", "category": "recon",
        "description": "Flujo de reconocimiento: nmap, subdominios y servicios.", "tags": "recon",
    })).await.unwrap();
    db.insert(COL_SKILLS, "pentest_report", serde_json::json!({
        "id": "pentest_report", "name": "pentest_report", "category": "report",
        "description": "Estructura un informe de pentest con exec summary.", "tags": "report",
    })).await.unwrap();

    // Coordinator context for a scan request: recon ranked, report_writer
    // present in the full catalog with its exclusion hint.
    let ctx = build_coordinator_context(&db, "escanear puertos del host 10.0.0.5").await;
    assert!(ctx.contains("recon_operator"), "recon should be ranked for a scan");
    assert!(ctx.contains("NO usar para"), "catalog must render exclusion hints");
    // The coordinator is not a worker → not in the roster.
    assert!(!ctx.contains("- caelum:"));

    // Skill context selects the recon playbook for a scan task.
    let sc = build_skill_context(&db, "escanear puertos y servicios del host").await;
    assert!(sc.contains("recon_workflow"), "recon skill selected for scan task");
    assert!(!sc.contains("pentest_report"), "unrelated report skill not selected");

    // Report task selects the report skill instead.
    let sc2 = build_skill_context(&db, "redacta el informe final del pentest en pdf").await;
    assert!(sc2.contains("pentest_report"));
}

// ---- Model catalog: per-model context window drives the compaction budget ----

#[tokio::test]
async fn test_resolve_context_budget_from_catalog() {
    use hivecyber_core::agent::models_catalog::{model_catalog, resolve_context_budget, sync_catalog};

    let db = temp_db().await;
    sync_catalog(&db).await;

    // hiveagents Qwen (ctx 50000) → budget = 50000 * 0.70 = 35000.
    let b = resolve_context_budget(&db, "hiveagents", "Qwen3.6-35B-A3B-UD-Q4_K_M.gguf", 24000).await;
    assert_eq!(b, 35_000);

    // A 1M-ctx anthropic model → 700000.
    let b2 = resolve_context_budget(&db, "anthropic", "claude-sonnet-5", 24000).await;
    assert_eq!(b2, 700_000);

    // Unknown model / empty → fallback.
    assert_eq!(resolve_context_budget(&db, "anthropic", "nope", 24000).await, 24000);
    assert_eq!(resolve_context_budget(&db, "anthropic", "", 24000).await, 24000);

    // Catalog is the full Hive mirror.
    assert!(model_catalog().len() >= 80);
}

// ---- Durable coordinator run: ensure / checkpoint / interrupt ----

#[tokio::test]
async fn test_run_lifecycle_ensure_checkpoint_interrupt() {
    use hivecyber_core::agent::run_store;

    let db = temp_db().await;

    // First ensure creates a running run for the thread.
    let rid = run_store::ensure_run(&db, "chat", "caelum", "th-1", serde_json::json!({"message":"go"}))
        .await
        .unwrap();
    let r = db.get(COL_RUNS, &rid).await.unwrap();
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("running"));

    // Second ensure for the same thread reuses the same run (no duplicate).
    let rid2 = run_store::ensure_run(&db, "chat", "caelum", "th-1", serde_json::json!({"message":"again"}))
        .await
        .unwrap();
    assert_eq!(rid, rid2, "same thread reuses its run");
    let all: Vec<_> = db.list(COL_RUNS).await;
    assert_eq!(all.len(), 1);

    // Checkpoint updates counters + lease.
    run_store::checkpoint_run(&db, &rid, 3, 1234, serde_json::json!({"turn":3})).await.unwrap();
    let r = db.get(COL_RUNS, &rid).await.unwrap();
    assert_eq!(r.get("iterations_used").and_then(|v| v.as_u64()), Some(3));
    assert_eq!(r.get("tokens_used").and_then(|v| v.as_u64()), Some(1234));
    assert!(r.get("lease_expires_at").and_then(|v| v.as_str()).is_some());

    // Interrupt marks it resumable.
    run_store::interrupt_run(&db, &rid).await.unwrap();
    let r = db.get(COL_RUNS, &rid).await.unwrap();
    assert_eq!(r.get("status").and_then(|v| v.as_str()), Some("interrupted"));

    // A fresh ensure for the same thread reactivates the interrupted run.
    let rid3 = run_store::ensure_run(&db, "chat", "caelum", "th-1", serde_json::json!({})).await.unwrap();
    assert_eq!(rid, rid3);
    assert_eq!(db.get(COL_RUNS, &rid).await.unwrap().get("status").and_then(|v| v.as_str()), Some("running"));
}

// ---- Audit chain: atomic append under concurrency (no forks) ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_audit_append_is_atomic_under_concurrency() {
    use hivecyber_core::security::audit;

    let db = temp_db().await;

    // Many concurrent writers hammering the chain. Without the global audit lock
    // several would read the same prev_hash and fork it.
    let mut handles = Vec::new();
    for i in 0..64 {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            audit::append_audit(&db, "nmap", &format!("10.0.0.{}", i), "recon_operator", "run-x", "op1")
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let entries = db.list(COL_AUDIT_LOG).await;
    assert_eq!(entries.len(), 64, "all appends persisted");

    let (ok, errors) = audit::verify_chain(&db).await.unwrap();
    assert!(ok, "chain must stay linear under concurrency; errors: {:?}", errors);
}

// ---- Acceptance: explicit structured evidence (typed, not regex) ----

#[tokio::test]
async fn test_acceptance_structured_evidence_items() {
    use hivecyber_core::agent::acceptance::{parse_evidence, run_acceptance_checks, verdict, CheckStatus, EvidenceItem};
    use hivecyber_core::store::collections::AcceptanceCriterion;

    // A worker emits explicit typed evidence (JSON), not free text.
    let evidence = vec![
        r#"{"type":"tool_run","tool":"nuclei","target":"10.0.0.5"}"#.into(),
        r#"{"type":"vulnerability","id":"CVE-2023-1234","severity":"high","title":"RCE"}"#.into(),
    ];
    let items = parse_evidence(&evidence);
    assert!(items.iter().any(|i| matches!(i, EvidenceItem::Vulnerability { id, .. } if id.as_deref() == Some("CVE-2023-1234"))));

    let acceptance = vec![AcceptanceCriterion {
        id: "vuln_findings".into(),
        description: "findings".into(),
        check_tool: Some("vuln_findings".into()),
    }];
    let checks = run_acceptance_checks("scan", &acceptance, "status: completed", &evidence);
    assert_eq!(verdict(&checks), CheckStatus::Passed, "typed CVE evidence must pass vuln_findings");

    // Structured exploit proof: an explicit shell session item.
    let ev2 = vec![r#"{"type":"shell_session","kind":"meterpreter"}"#.into()];
    let acc2 = vec![AcceptanceCriterion {
        id: "exploit_proof".into(),
        description: "proof".into(),
        check_tool: Some("exploit_proof".into()),
    }];
    assert_eq!(
        verdict(&run_acceptance_checks("x", &acc2, "done", &ev2)),
        CheckStatus::Passed
    );

    // Structured intel correlation with 2 cited sources passes without needing
    // two distinct tool runs.
    let ev3 = vec![r#"{"type":"correlation","indicator":"1.2.3.4","sources":["shodan","virustotal"]}"#.into()];
    let acc3 = vec![AcceptanceCriterion {
        id: "intel_correlation".into(),
        description: "corr".into(),
        check_tool: Some("intel_correlation".into()),
    }];
    assert_eq!(
        verdict(&run_acceptance_checks("x", &acc3, "done", &ev3)),
        CheckStatus::Passed
    );

    // Insufficient: a vulnerability item with neither id nor severity fails.
    let ev4 = vec![r#"{"type":"vulnerability","title":"maybe"}"#.into()];
    let acc4 = vec![AcceptanceCriterion {
        id: "vuln_findings".into(),
        description: "findings".into(),
        check_tool: Some("vuln_findings".into()),
    }];
    assert_eq!(
        verdict(&run_acceptance_checks("x", &acc4, "done", &ev4)),
        CheckStatus::Failed
    );
}

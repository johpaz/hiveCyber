use hivecyber_core::store::HiveDb;
use hivecyber_core::store::collections::*;
use hivecyber_core::agent::catalog;
use hivecyber_core::agent::stuck::StuckLoopDetector;
use hivecyber_core::agent::acceptance::{run_acceptance_checks, verdict, CheckStatus};
use hivecyber_core::security::{policies, audit};
use std::path::PathBuf;

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
fn test_acceptance_no_checktool_is_unchecked() {
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
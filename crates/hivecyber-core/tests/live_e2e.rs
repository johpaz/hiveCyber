//! E2E en vivo (sin LLM) contra Juice Shop en 127.0.0.1:3000 con herramientas
//! reales en PATH. Ignorado por defecto:
//!   PATH=<shims>:$PATH cargo test -p hivecyber-core --test live_e2e -- --ignored --nocapture
//! Ejercita: política real, middleware (gates + audit), tools de recon reales,
//! bloqueos, pipeline de hallazgos/reporte y verificación de la cadena de audit.

use hivecyber_core::findings::{self, render_report, FindingsBackend};
use hivecyber_core::security::audit;
use hivecyber_core::tool_runtime::{execute_tool_batch_audited, AuditCtx, ToolMiddleware};
use hivecyber_core::HiveDb;
use hivecyber_tools::engagement::{EngagementPolicy, ProhibitedActivity};
use hivecyber_tools::{SecurityContext, ToolRegistry};
use std::sync::Arc;

fn load_policy() -> EngagementPolicy {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../e2e/engagement-policy.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn sec(policy: EngagementPolicy, root: &std::path::Path) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        unsafe_mode: true,
        allow_cli_exec: true,
        operator_id: "e2e".into(),
        engagement_policy: Some(Arc::new(policy)),
        task_root: Some(root.to_path_buf()),
        ..Default::default()
    })
}

async fn call(
    reg: &ToolRegistry,
    mw: &ToolMiddleware,
    ctx: &AuditCtx,
    tool: &str,
    args: serde_json::Value,
) -> hivecyber_core::tool_runtime::batch::ToolBatchResult {
    let mut r = execute_tool_batch_audited(vec![(tool.into(), args)], reg, 120_000, mw, ctx).await;
    r.remove(0)
}

#[tokio::test]
#[ignore]
async fn live_recon_gates_findings_and_audit() {
    let tmp = tempfile::tempdir().unwrap();
    let db = HiveDb::open(&tmp.path().join("db")).await.unwrap();
    let ctx = AuditCtx { worker: "recon_operator".into(), run_id: "live-1".into(), operator_id: "e2e".into() };

    // ── 1) política del e2e: recon real contra Juice Shop ─────────────────────
    let s1 = sec(load_policy(), tmp.path());
    let reg1 = ToolRegistry::create_with_security(s1.clone());
    let mw1 = ToolMiddleware::new(db.clone(), s1.clone());

    let r = call(&reg1, &mw1, &ctx, "httpx", serde_json::json!({"target": "http://127.0.0.1:3000", "flags": "-sc -title -td"})).await;
    println!("httpx  → success={} {}", r.success, r.result);
    assert!(r.success, "{:?}", r.error);
    let out = r.result["stdout"].as_str().unwrap_or("");
    assert!(out.contains("200"), "httpx no vio un 200: {out}");

    // El gate de main bloquea rastreadores si la política prohíbe DoS o escaneo
    // automatizado; la política del e2e prohíbe DoS → katana debe bloquearse.
    let r = call(&reg1, &mw1, &ctx, "katana", serde_json::json!({"target": "http://127.0.0.1:3000/", "flags": "-d 1"})).await;
    println!("katana (política e2e, prohíbe DoS) → bloqueado={:?}", r.error.as_deref().map(|e| &e[..40.min(e.len())]));
    assert!(!r.success && r.error.unwrap_or_default().contains("escaneo/fuerza bruta"));

    // Sin esa prohibición, katana corre de verdad y rastrea Juice Shop.
    let mut relaxed = load_policy();
    relaxed.prohibited.retain(|p| *p != ProhibitedActivity::DenialOfService);
    let sr = sec(relaxed, tmp.path());
    let regr = ToolRegistry::create_with_security(sr.clone());
    let mwr = ToolMiddleware::new(db.clone(), sr.clone());
    let r = call(&regr, &mwr, &ctx, "katana", serde_json::json!({"target": "http://127.0.0.1:3000/", "flags": "-d 1"})).await;
    let lines = r.result["stdout"].as_str().unwrap_or("").lines().count();
    println!("katana (política relajada) → success={} urls={} err={:?}", r.success, lines, r.error);
    assert!(r.success, "{:?}", r.error);
    assert!(lines > 0, "katana no encontró URLs: {}", r.result);

    // ── 2) fuera de scope: bloqueado ──────────────────────────────────────────
    let r = call(&reg1, &mw1, &ctx, "httpx", serde_json::json!({"target": "http://example.org"})).await;
    println!("httpx example.org → {}", r.result);
    assert!(r.result["error"] == "security_policy" || !r.success, "fuera de scope no se bloqueó");

    // ── 3) inyección por path: no ejecuta nada ────────────────────────────────
    let flag = tmp.path().join("pwned");
    let r = call(&reg1, &mw1, &ctx, "httpx",
        serde_json::json!({"target": format!("http://127.0.0.1:3000/x;touch {}", flag.display())})).await;
    println!("httpx con ';touch' → success={}", r.success);
    assert!(!flag.exists(), "¡inyección de comandos ejecutada!");

    // ── 4) la política prohíbe escaneo automatizado: el gate bloquea ──────────
    let mut strict = load_policy();
    strict.prohibited.push(ProhibitedActivity::AutomatedScanning);
    let s2 = sec(strict, tmp.path());
    let reg2 = ToolRegistry::create_with_security(s2.clone());
    let mw2 = ToolMiddleware::new(db.clone(), s2.clone());
    let r = call(&reg2, &mw2, &ctx, "httpx", serde_json::json!({"target": "http://127.0.0.1:3000"})).await;
    println!("httpx con automated_scanning prohibido → {:?}", r.error);
    assert!(!r.success);
    let msg = r.error.clone().unwrap_or_default();
    assert!(msg.contains("automated") || msg.contains("prohíbe") || msg.contains("escane"), "{msg}");

    // ── 5) hallazgos: scope, dedup, redacción, reporte ────────────────────────
    let pol = load_policy();
    let be = FindingsBackend { db: db.clone(), policy: Some(Arc::new(pol.clone())), created_by: "recon_operator".into() };
    use hivecyber_tools::findings::FindingsBackend as _;
    let a = be.submit(serde_json::json!({
        "vulnerability": "Sensitive Data Exposure", "host": "127.0.0.1:3000", "endpoint": "/ftp",
        "severity": "medium", "title": "Directorio /ftp listable",
        "reproduction": "GET http://127.0.0.1:3000/ftp con Authorization: Bearer abcdefghijklmnop1234 lista archivos",
        "evidence": ["GET /ftp -> 200"]
    })).await.unwrap();
    println!("finding → {a}");
    assert_eq!(a["status"], "needs_human_review");
    let b = be.submit(serde_json::json!({
        "vulnerability": "sensitive-data-exposure", "host": "127.0.0.1", "endpoint": "/ftp/", "severity": "medium",
        "reproduction": "mismo bug"
    })).await.unwrap();
    assert_eq!(b["status"], "possible_duplicate", "{b}");
    let oos = be.submit(serde_json::json!({"vulnerability": "xss", "host": "evil.example.org", "reproduction": "x"})).await;
    assert!(oos.is_err(), "un hallazgo fuera de scope debe rechazarse");

    let id = a["id"].as_str().unwrap();
    let f: findings::Finding = serde_json::from_value(db.get("findings", id).await.unwrap()).unwrap();
    let md = render_report(&f, pol.ai_policy.disclosure_required);
    println!("--- reporte ---\n{md}");
    assert!(md.contains("BORRADOR"));
    assert!(!md.contains("abcdefghijklmnop1234"), "el token debe estar redactado");

    // ── 6) la cadena de audit cubre TODOS los intentos y verifica ─────────────
    let n = db.count("audit_log").await;
    let (ok, errs) = audit::verify_chain(&db).await.unwrap();
    println!("audit: {n} entradas, cadena ok={ok} {errs:?}");
    assert!(ok, "{errs:?}");
    assert!(n >= 5, "se esperaban ≥5 intentos auditados, hay {n}");
}

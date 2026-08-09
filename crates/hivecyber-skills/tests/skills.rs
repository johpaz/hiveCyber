use hivecyber_skills::SkillLoader;
use std::path::PathBuf;

fn bundled_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../skills/bundled")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("./skills/bundled"))
}

#[test]
fn test_skill_loader_loads_bundled() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().expect("should load bundled skills");

    let skills = loader.list();
    assert!(
        skills.len() >= 12,
        "expected 12+ bundled skills, got {}",
        skills.len()
    );
}

#[test]
fn test_skill_recon_workflow_exists() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    let skill = loader.get("recon_workflow").expect("recon_workflow should exist");
    assert_eq!(skill.category, "recon");
    assert!(!skill.description.is_empty());
    assert!(!skill.body.is_empty());
    assert!(skill.tools.contains(&"nmap".to_string()));
}

#[test]
fn test_skill_pwn_check_has_exploit_category() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    let skill = loader.get("pwn_check").expect("pwn_check should exist");
    assert_eq!(skill.category, "exploit");
    assert!(skill.tools.contains(&"metasploit_rpc".to_string()));
}

#[test]
fn test_skill_memory_analysis_has_forensics_category() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    let skill = loader.get("memory_analysis").expect("memory_analysis should exist");
    assert_eq!(skill.category, "forensics");
    assert!(skill.tools.contains(&"volatility".to_string()));
}

#[test]
fn test_skill_cvss_scoring_has_reporting_category() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    let skill = loader.get("cvss_scoring").expect("cvss_scoring should exist");
    assert_eq!(skill.category, "reporting");
}

#[test]
fn test_skill_all_categories_present() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    let categories: std::collections::HashSet<&str> =
        loader.list().iter().map(|s| s.category.as_str()).collect();
    assert!(categories.contains("recon"));
    assert!(categories.contains("vulns"));
    assert!(categories.contains("exploit"));
    assert!(categories.contains("forensics"));
    assert!(categories.contains("reporting"));
    assert!(categories.contains("tradecraft"));
}

#[test]
fn test_skill_source_is_bundled() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    for skill in loader.list() {
        assert_eq!(
            skill.source, "bundled",
            "skill '{}' should have source='bundled'",
            skill.name
        );
    }
}

#[test]
fn test_skill_nonexistent_returns_none() {
    let bundled = bundled_dir();
    let managed = PathBuf::from("/tmp/hc_skills_managed_nonexist");
    let mut loader = SkillLoader::new(&bundled, &managed);
    loader.load_all().unwrap();

    assert!(loader.get("nonexistent_skill_xyz").is_none());
}
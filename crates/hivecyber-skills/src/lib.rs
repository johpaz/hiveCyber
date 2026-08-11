use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Skill {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    pub description: String,
    #[serde(default)]
    pub icon: Option<String>,
    pub category: String,
    #[serde(default)]
    pub triggers: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub preferred_agents: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<serde_json::Value>,
    #[serde(skip)]
    pub source: String,
    #[serde(skip)]
    pub body: String,
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

pub struct SkillLoader {
    bundled_dir: PathBuf,
    managed_dir: PathBuf,
    extra_dirs: Vec<PathBuf>,
    cache: HashMap<String, Skill>,
}

impl SkillLoader {
    pub fn new(bundled_dir: &Path, managed_dir: &Path) -> Self {
        SkillLoader {
            bundled_dir: bundled_dir.to_path_buf(),
            managed_dir: managed_dir.to_path_buf(),
            extra_dirs: Vec::new(),
            cache: HashMap::new(),
        }
    }

    pub fn add_extra_dir(&mut self, dir: &Path) {
        self.extra_dirs.push(dir.to_path_buf());
    }

    pub fn load_all(&mut self) -> Result<()> {
        self.cache.clear();

        self.load_from_dir(&self.bundled_dir.clone(), "bundled")?;
        self.load_from_dir(&self.managed_dir.clone(), "managed")?;
        let extra_dirs: Vec<PathBuf> = self.extra_dirs.clone();
        for dir in &extra_dirs {
            self.load_from_dir(dir, "extra")?;
        }

        Ok(())
    }

    fn load_from_dir(&mut self, dir: &Path, source: &str) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("SKILL.md") {
                match self.load_skill_file(path, source) {
                    Ok(skill) => {
                        self.cache.insert(skill.name.clone(), skill);
                    }
                    Err(e) => {
                        eprintln!("[WARN] failed to load skill {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(())
    }

    fn load_skill_file(&self, path: &Path, source: &str) -> Result<Skill> {
        let raw = std::fs::read_to_string(path).context("read skill file")?;
        // Normalize CRLF → LF before parsing. A SKILL.md checked out on Windows
        // (git's default core.autocrlf converts LF→CRLF) or authored there via
        // `skills add` would otherwise fail the frontmatter regex below, which
        // matches a literal `\n` — `---\r\n` never matches `^---\n`.
        let content = raw.replace("\r\n", "\n");

        let re = Regex::new(r"(?s)^---\n(.*?)\n---\n(.*)$").unwrap();
        let caps = re
            .captures(&content)
            .ok_or_else(|| anyhow::anyhow!("invalid SKILL.md format: no frontmatter"))?;

        let frontmatter: serde_yaml::Value = serde_yaml::from_str(&caps[1])?;
        let body = caps[2].trim().to_string();

        let mut skill: Skill = serde_yaml::from_value(frontmatter)?;
        skill.source = source.to_string();
        skill.body = body;
        skill.path = Some(path.to_path_buf());

        Ok(skill)
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.cache.get(name)
    }

    pub fn list(&self) -> Vec<&Skill> {
        let mut skills: Vec<&Skill> = self.cache.values().collect();
        skills.sort_by(|a, b| a.name.cmp(&b.name));
        skills
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the Windows CI failure: git checks out repo files with CRLF
    /// (default `core.autocrlf=true`), and a SKILL.md authored/edited on
    /// Windows via `skills add` would have CRLF too. The frontmatter parser
    /// must accept both.
    #[test]
    fn load_skill_file_accepts_crlf_line_endings() {
        let dir = std::env::temp_dir().join(format!("hc_skill_crlf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("SKILL.md");

        let crlf_content = "---\r\nname: crlf_test\r\ndescription: prueba CRLF\r\ncategory: recon\r\nversion: \"1.0\"\r\n---\r\n# Body\r\nContenido con CRLF.\r\n";
        std::fs::write(&path, crlf_content).unwrap();

        let loader = SkillLoader::new(&dir, &dir);
        let skill = loader
            .load_skill_file(&path, "test")
            .expect("CRLF frontmatter must parse, not fail with 'no frontmatter'");
        assert_eq!(skill.name, "crlf_test");
        assert!(skill.body.contains("Contenido con CRLF"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_skill_file_still_accepts_lf_line_endings() {
        let dir = std::env::temp_dir().join(format!("hc_skill_lf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("SKILL.md");

        let lf_content = "---\nname: lf_test\ndescription: prueba LF\ncategory: recon\nversion: \"1.0\"\n---\n# Body\nContenido con LF.\n";
        std::fs::write(&path, lf_content).unwrap();

        let loader = SkillLoader::new(&dir, &dir);
        let skill = loader.load_skill_file(&path, "test").expect("LF frontmatter must keep parsing");
        assert_eq!(skill.name, "lf_test");

        std::fs::remove_dir_all(&dir).ok();
    }
}

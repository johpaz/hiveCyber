//! Capability search — BM25 over a unified capability index.
//!
//! Rust port of Hive's `capability-search.ts`: one in-memory tantivy index for
//! tools, skills, agents (and, later, MCP tools / playbooks), discriminated by
//! a `type` field. Per-field BM25 boosts (name 4, tags 3, body 2), a Spanish
//! analyzer (accent folding + stemming), and a relative-cutoff helper so
//! relevance is judged against the top hit rather than an absolute floor.

use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, STORED, STRING};
use tantivy::tokenizer::{
    AsciiFoldingFilter, Language, LowerCaser, RemoveLongFilter, SimpleTokenizer, Stemmer,
    TextAnalyzer,
};
use tantivy::{Index, TantivyDocument};

pub const ES_ANALYZER: &str = "es";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityType {
    Tool,
    Skill,
    Agent,
    Mcp,
    Playbook,
}

impl CapabilityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityType::Tool => "tool",
            CapabilityType::Skill => "skill",
            CapabilityType::Agent => "agent",
            CapabilityType::Mcp => "mcp",
            CapabilityType::Playbook => "playbook",
        }
    }
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "tool" => Some(CapabilityType::Tool),
            "skill" => Some(CapabilityType::Skill),
            "agent" => Some(CapabilityType::Agent),
            "mcp" => Some(CapabilityType::Mcp),
            "playbook" => Some(CapabilityType::Playbook),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityDoc {
    pub typ: CapabilityType,
    /// Id within the type namespace (tool name, agent id, skill id…).
    pub raw_id: String,
    pub name: String,
    pub tags: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct CapabilityHit {
    pub typ: CapabilityType,
    pub raw_id: String,
    pub score: f32,
}

/// An immutable, in-memory capability index. Rebuild it when the underlying
/// tool/agent/skill set changes — building is cheap for the small catalogs
/// this harness has (< a few hundred docs).
pub struct CapabilityIndex {
    index: Index,
    id: tantivy::schema::Field,
    typ: tantivy::schema::Field,
    name: tantivy::schema::Field,
    tags: tantivy::schema::Field,
    body: tantivy::schema::Field,
}

impl CapabilityIndex {
    pub fn build(docs: &[CapabilityDoc]) -> anyhow::Result<Self> {
        let mut sb = Schema::builder();
        let id = sb.add_text_field("id", STRING | STORED);
        let typ = sb.add_text_field("typ", STRING | STORED);

        let text_opts = TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer(ES_ANALYZER)
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        );
        let name = sb.add_text_field("name", text_opts.clone());
        let tags = sb.add_text_field("tags", text_opts.clone());
        let body = sb.add_text_field("body", text_opts);
        let schema = sb.build();

        let index = Index::create_in_ram(schema);
        register_es_analyzer(&index);

        {
            let mut writer = index.writer(15_000_000)?;
            for d in docs {
                let mut tdoc = TantivyDocument::default();
                tdoc.add_text(id, format!("{}:{}", d.typ.as_str(), d.raw_id));
                tdoc.add_text(typ, d.typ.as_str());
                tdoc.add_text(name, &d.name);
                tdoc.add_text(tags, &d.tags);
                tdoc.add_text(body, &d.body);
                writer.add_document(tdoc)?;
            }
            writer.commit()?;
        }

        Ok(CapabilityIndex { index, id, typ, name, tags, body })
    }

    /// Search with raw user text. `types` restricts the result set (empty = all).
    /// Returns up to `k` hits sorted by descending BM25 score.
    pub fn search(&self, query: &str, types: &[CapabilityType], k: usize) -> Vec<CapabilityHit> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let reader = match self.index.reader() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let searcher = reader.searcher();

        let mut qp = QueryParser::for_index(&self.index, vec![self.name, self.tags, self.body]);
        qp.set_field_boost(self.name, 4.0);
        qp.set_field_boost(self.tags, 3.0);
        qp.set_field_boost(self.body, 2.0);

        // Lenient parse: accents/quotes/operators/punctuation never throw — the
        // caller must not pre-sanitize (same contract as Hive's searchCapabilities).
        let (parsed, _errs) = qp.parse_query_lenient(trimmed);

        // Over-fetch, then filter by requested type in Rust (corpus is small).
        let limit = (k.max(1)) * 4;
        let top = match searcher.search(&parsed, &TopDocs::with_limit(limit)) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let mut hits = Vec::new();
        for (score, addr) in top {
            let doc: TantivyDocument = match searcher.doc(addr) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let type_str = doc
                .get_first(self.typ)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let Some(ct) = CapabilityType::from_str(type_str) else { continue };
            if !types.is_empty() && !types.contains(&ct) {
                continue;
            }
            let id_str = doc.get_first(self.id).and_then(|v| v.as_str()).unwrap_or("");
            let raw_id = id_str.split_once(':').map(|(_, r)| r).unwrap_or(id_str).to_string();
            hits.push(CapabilityHit { typ: ct, raw_id, score });
            if hits.len() >= k {
                break;
            }
        }
        hits
    }
}

fn register_es_analyzer(index: &Index) {
    let es = TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(RemoveLongFilter::limit(40))
        .filter(LowerCaser)
        .filter(AsciiFoldingFilter)
        .filter(Stemmer::new(Language::Spanish))
        .build();
    index.tokenizers().register(ES_ANALYZER, es);
}

/// Keep only hits scoring at least `ratio` of the top hit — relevance is
/// relative to the best match, never an absolute floor (BM25 magnitude depends
/// on corpus and document length). Mirrors Hive's `applyRelativeCutoff`.
pub fn apply_relative_cutoff(hits: Vec<CapabilityHit>, ratio: f32) -> Vec<CapabilityHit> {
    if hits.is_empty() {
        return hits;
    }
    let top = hits[0].score;
    if top <= 0.0 {
        return Vec::new();
    }
    hits.into_iter().filter(|h| h.score >= ratio * top).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_docs() -> Vec<CapabilityDoc> {
        vec![
            CapabilityDoc {
                typ: CapabilityType::Tool,
                raw_id: "nmap".into(),
                name: "nmap".into(),
                tags: "recon escaneo puertos red network scan".into(),
                body: "Escaneo de red con nmap. Descubre puertos y servicios.".into(),
            },
            CapabilityDoc {
                typ: CapabilityType::Tool,
                raw_id: "sqlmap".into(),
                name: "sqlmap".into(),
                tags: "vulnerabilidad inyeccion sql web injection".into(),
                body: "Detecta y explota inyecciones SQL en aplicaciones web.".into(),
            },
            CapabilityDoc {
                typ: CapabilityType::Tool,
                raw_id: "office_write".into(),
                name: "office_write".into(),
                tags: "informe reporte documento docx pdf".into(),
                body: "Genera informes en docx, pdf y xlsx.".into(),
            },
            CapabilityDoc {
                typ: CapabilityType::Agent,
                raw_id: "recon_operator".into(),
                name: "Operador de Reconocimiento recon_operator".into(),
                tags: "nmap shodan osint reconocimiento".into(),
                body: "Ejecuta reconocimiento activo y OSINT sobre targets.".into(),
            },
        ]
    }

    #[test]
    fn ranks_relevant_tool_first_with_accents_and_stemming() {
        let idx = CapabilityIndex::build(&sample_docs()).unwrap();
        // Query with an accent and a different inflection ("escanear" vs "escaneo").
        let hits = idx.search("escanear puertos de red", &[CapabilityType::Tool], 5);
        assert!(!hits.is_empty(), "should find at least one tool");
        assert_eq!(hits[0].raw_id, "nmap", "nmap should rank first");
    }

    #[test]
    fn type_filter_restricts_results() {
        let idx = CapabilityIndex::build(&sample_docs()).unwrap();
        let tool_hits = idx.search("reconocimiento", &[CapabilityType::Tool], 5);
        assert!(tool_hits.iter().all(|h| h.typ == CapabilityType::Tool));

        let agent_hits = idx.search("reconocimiento nmap", &[CapabilityType::Agent], 5);
        assert!(!agent_hits.is_empty());
        assert_eq!(agent_hits[0].raw_id, "recon_operator");
    }

    #[test]
    fn report_query_finds_office_tool() {
        let idx = CapabilityIndex::build(&sample_docs()).unwrap();
        let hits = idx.search("generar informe pdf", &[CapabilityType::Tool], 5);
        assert_eq!(hits[0].raw_id, "office_write");
    }

    #[test]
    fn relative_cutoff_drops_weak_hits() {
        let hits = vec![
            CapabilityHit { typ: CapabilityType::Tool, raw_id: "a".into(), score: 10.0 },
            CapabilityHit { typ: CapabilityType::Tool, raw_id: "b".into(), score: 4.0 },
            CapabilityHit { typ: CapabilityType::Tool, raw_id: "c".into(), score: 1.0 },
        ];
        let kept = apply_relative_cutoff(hits, 0.3);
        assert_eq!(kept.len(), 2, "only hits >= 30% of top (>=3.0) survive");
    }

    #[test]
    fn empty_query_returns_nothing() {
        let idx = CapabilityIndex::build(&sample_docs()).unwrap();
        assert!(idx.search("   ", &[], 5).is_empty());
    }
}

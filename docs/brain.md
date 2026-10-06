# El Cerebro de hiveCyber (capa de conocimiento)

> Recuperación semántica sobre un corpus curado de **metodología, scope de programa e
> histórico de hallazgos**, para que Caelum y los workers fundamenten *cómo* trabajan —
> no solo *qué tool* usar.

## Por qué

hiveCyber ya tiene búsqueda BM25/tantivy, pero indexa **capacidades**: `tool-selector`,
`catalog-selector` (routing de workers) y `skill-selector`. Eso responde a *"¿qué puedo
usar?"*. Falta lo complementario: *"¿qué sé sobre este tipo de bug, qué permite este
programa, y ya reporté algo parecido antes?"*.

El cerebro añade tres cuerpos de conocimiento recuperables:

1. **Playbooks de metodología** — por clase de vulnerabilidad: qué es, dónde vive, cómo se
   detecta, cómo se evidencia, remediación, referencias (OWASP WSTG / API Top 10 / LLM Top
   10 / CWE). Conocimiento defensivo y educativo, sin payloads.
2. **Scope del programa** — reglas de enganche ingeridas por engagement (hosts, exclusiones,
   actividades prohibidas, política de IA, ventanas). Esto ya lo tienes como
   `EngagementPolicy`; el cerebro lo hace **consultable en lenguaje natural** por el agente.
3. **Memoria de hallazgos** — histórico tipado de lo encontrado, con campos de deduplicación.
   Antes de reportar, el agente consulta: *"¿esto se parece a un finding previo?"*.

## Dónde encaja en la arquitectura

Reutiliza lo que ya existe, no inventa infra nueva:

| Pieza nueva | Reusa |
|---|---|
| `COL_KNOWLEDGE` (colección HiveDB) | mismo document store JSON-on-files |
| Índice híbrido `knowledge` | `hivedb-index` de [hiveBD](https://github.com/johpaz/hiveBD): `upsert_doc` / `query_hybrid` con `ScalarFilter` por `kind` y `program` |
| `knowledge-selector` (4º selector BM25) | misma trilogía tool/catalog/skill-selector |
| Ingesta de scope | deriva de `EngagementPolicy` (`tools/src/engagement.rs`) |
| Memoria de findings | extiende los `EvidenceItem` tipados que ya emiten los workers |

```
┌─────────────────────────────────────────────┐
│ Caelum (coordinador)                         │
│   ├─ tool-selector      → ¿qué tool?         │
│   ├─ catalog-selector   → ¿qué worker?       │
│   ├─ skill-selector     → ¿qué workflow?     │
│   └─ knowledge-selector → ¿qué SÉ? (nuevo)   │◄── COL_KNOWLEDGE + hiveBD
└─────────────────────────────────────────────┘
                     │
          playbooks · scope · findings
```

## Modelo de datos

Cada documento en `COL_KNOWLEDGE` lleva frontmatter YAML + cuerpo Markdown, igual que las
skills bundled, con un campo `kind` que discrimina el tipo:

```yaml
---
id: pb-idor
kind: playbook          # playbook | scope | finding | checklist
title: "IDOR / Broken Object Level Authorization"
tags: [access-control, api, web, owasp-api1]
refs: [OWASP-API1:2023, CWE-639]
severity_hint: high
program: null           # null = general; o el slug del engagement
---
(cuerpo Markdown: qué es, dónde, detección, evidencia, remediación, referencias)
```

- **playbook** → corpus general, versionado en el repo bajo `knowledge/playbooks/`.
- **scope** → generado por engagement desde la `EngagementPolicy`; no se commitea.
- **finding** → escrito por los workers al cerrar un `EvidenceItem`; privado por engagement.
- **checklist** → listas de verificación accionables, bajo `knowledge/checklists/`.

## Ingesta

```
# Corpus general (playbooks + checklists versionados)
hivecyber knowledge ingest ./knowledge

# Scope de un engagement, derivado de su política
hivecyber knowledge ingest-scope --engagement-policy engagements/acme/engagement-policy.json

# Los findings se ingieren solos: al emitir un EvidenceItem, el worker
# hace knowledge.write(kind=finding, program=<slug>, dedup_key=...)
```

## Gate de deduplicación

Los hallazgos viven tipados en `COL_FINDINGS` (autoritativo) y se proyectan como documentos
`kind=finding` del cerebro. Los workers (`vuln_scanner`, `web_pentester`, `exploit_operator`) los
registran con la tool **`finding_record`**, que compara con los hallazgos previos *del mismo programa*
antes de guardar:

| Resultado | Condición | Efecto |
|---|---|---|
| `duplicate` | misma `dedup_key` | **no se guarda**; devuelve el id original |
| `possible_duplicate` | similitud ≥ `knowledge.dedup_threshold` (0.72) | se guarda **retenido**; no es reportable |
| `new` | resto | `draft` si no hay reproducción; si la hay, `needs_human_review` (o `ready` si el programa permite envío autónomo) |

- `dedup_key` = sha256 (24 hex) de programa + clase normalizada + host + endpoint normalizado
  (`/api/orders/123` → `/api/orders/{id}`) + parámetro. Alias de clase: `BOLA` y `Broken Object Level
  Authorization` → `idor`.
- La similitud **no usa el score BM25** (sin cota en modo texto): es
  `misma_clase × mismo_host × (0.8·jaccard(segmentos del endpoint) + 0.2·mismo_parámetro)`, así que el
  umbral es interpretable. Mismo endpoint con otro parámetro = 0.8 (posible duplicado); otro endpoint de
  la misma clase = distinto hallazgo.
- Un hallazgo `rejected`/`duplicate` previo sigue contando: re-encontrarlo es duplicado.
- El `report_writer` consulta **`finding_list`** antes de redactar. Esa tool solo devuelve lo reportable
  (borradores y posibles duplicados quedan fuera, solo se informa cuántos) y adjunta evidencia tipada
  (`findings_reviewed`) que exige el criterio de aceptación `findings_cleared`.
- Revisión humana: `hivecyber knowledge findings` y `hivecyber knowledge finding-set <id> <status>`.

## Política de IA por programa

```json
"ai_policy": { "disclosure_required": true, "autonomous_submission_allowed": false },
"knowledge": { "ingest_scope_on_load": true, "dedup_threshold": 0.72 }
```

Ambos bloques son opcionales (`#[serde(default)]`); los defaults son los conservadores.

- **Prompt**: coordinador y workers reciben un bloque "Política de IA del programa" (declarar uso de IA;
  no enviar, dejar en borrador).
- **Bloqueo real** (`tool_runtime::middleware::submission_gate`): con `autonomous_submission_allowed=false`
  y una política cargada, las tools de envío (`*submit_finding*`, `*submit_report*`, …; p. ej.
  `bugcrowd_submit_finding`) se rechazan, y el rechazo queda auditado. El operador puede autorizar un run
  con `--approve-human submit_report`.

## Esqueleto de implementación (Rust)

No hay crate ni índice tantivy propios: el módulo vive en `hivecyber-core` y delega en hiveBD
(`hivedb-core` ≥ 0.5.1), que ya aporta colecciones con versionado, BM25 + ANN + RRF y filtros escalares.

```rust
// crates/hivecyber-core/src/knowledge/mod.rs
pub enum KnowledgeKind { Playbook, Scope, Finding, Checklist }

pub struct KnowledgeDoc {
    pub id: String,
    pub kind: KnowledgeKind,
    pub title: String,
    pub tags: Vec<String>,
    pub refs: Vec<String>,
    pub program: Option<String>,   // None = general ("_general" en el filtro)
    pub body: String,
    pub dedup_key: Option<String>, // para kind=Finding
}

// ingest: col_put(COL_KNOWLEDGE, ..) + upsert_doc(IndexDoc { name: title, body, tags,
//         filters: [Eq("kind", ..), Eq("program", ..)] })
// search: query_hybrid(HybridQuery { text, filters: [Eq("kind", ..)], .. })
```

> El filtro escalar solo soporta igualdad: para "general + programa" se hacen dos consultas y se fusionan.
> Sin embeddings el score es BM25 crudo (sin cota), así que `dedup_threshold` se aplica sobre un score normalizado.

Y el `knowledge-selector` se registra en el loop junto a los otros tres selectores, inyectando
los top-N playbooks relevantes al prompt del worker que toma la tarea.

## Resumen

El cerebro no cambia tu arquitectura: le añade la pata de *conocimiento* a una trilogía que
hoy solo cubre *capacidad*. Playbooks curados fundamentan el método, el scope consultable
mantiene al agente dentro de las reglas, y la memoria de findings con dedup gate es tu
defensa contra el AI slop.

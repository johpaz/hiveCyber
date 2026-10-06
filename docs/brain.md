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

## Gate de deduplicación (antes de reportar)

El `report_writer` consulta el cerebro **antes** de redactar:

1. `knowledge.search(kind=finding, program=<slug>, query=<resumen del hallazgo>)`.
2. Si hay match sobre un umbral → marca el finding como **posible duplicado** y requiere
   revisión humana en vez de generar reporte.
3. Si no → procede, pero exige PoC reproducible (ya tienes acceptance por `EvidenceItem`).

Esto ataca directamente el problema de 2026: las plataformas endurecieron reglas contra el
volumen de reportes duplicados/IA. El cerebro convierte "no duplicar" en un control, no en
una esperanza.

## Política de IA por programa

Añade a la `EngagementPolicy` un campo que el cerebro expone al coordinador:

```json
"ai_policy": { "disclosure_required": true, "autonomous_submission_allowed": false }
```

Caelum lo lee vía `routing_context` (como ya hace con `routing_exclusions`) y ajusta el
comportamiento: si `autonomous_submission_allowed=false`, el pipeline **se detiene en
borrador** y entrega al operador humano.

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

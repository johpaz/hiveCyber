// Office document tools (report_writer): read/write docx, xlsx, pdf and plain
// text. Format is inferred from the file extension. The underlying crates are
// synchronous, so file work runs on `spawn_blocking` to avoid stalling the
// async runtime.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;

use crate::registry::{Tool, ToolCategory, ToolSchema};

fn ext_of(path: &str) -> String {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// office_read
// ---------------------------------------------------------------------------

pub struct OfficeRead;

#[async_trait]
impl Tool for OfficeRead {
    fn name(&self) -> &str { "office_read" }
    fn description(&self) -> &str {
        "Lee un documento de oficina (docx, xlsx/xls/ods, pdf) o texto y retorna su contenido."
    }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: Some(vec!["path".into()]) }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("path required"))?
            .to_string();

        let out = tokio::task::spawn_blocking(move || read_office(&path))
            .await
            .map_err(|e| anyhow!("join error: {}", e))?;
        Ok(out)
    }
}

fn read_office(path: &str) -> Value {
    match ext_of(path).as_str() {
        "xlsx" | "xls" | "ods" | "xlsm" => read_spreadsheet(path),
        "docx" => read_docx(path),
        "pdf" => read_pdf(path),
        _ => match std::fs::read_to_string(path) {
            Ok(text) => json!({"path": path, "format": "text", "content": text}),
            Err(e) => json!({"path": path, "error": "read_failed", "message": e.to_string()}),
        },
    }
}

fn read_spreadsheet(path: &str) -> Value {
    use calamine::{open_workbook_auto, Reader};

    let mut wb = match open_workbook_auto(path) {
        Ok(w) => w,
        Err(e) => return json!({"path": path, "error": "open_failed", "message": e.to_string()}),
    };
    let mut sheets = Vec::new();
    for name in wb.sheet_names().to_owned() {
        if let Ok(range) = wb.worksheet_range(&name) {
            let rows: Vec<Vec<String>> = range
                .rows()
                .map(|row| row.iter().map(|c| c.to_string()).collect())
                .collect();
            sheets.push(json!({"name": name, "rows": rows.len(), "data": rows}));
        }
    }
    json!({"path": path, "format": "spreadsheet", "sheets": sheets})
}

fn read_docx(path: &str) -> Value {
    // A .docx is a zip; the body text lives in word/document.xml inside <w:t> runs.
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return json!({"path": path, "error": "open_failed", "message": e.to_string()}),
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => return json!({"path": path, "error": "not_a_docx", "message": e.to_string()}),
    };
    let mut xml = String::new();
    if let Ok(mut entry) = zip.by_name("word/document.xml") {
        let _ = entry.read_to_string(&mut xml);
    } else {
        return json!({"path": path, "error": "no_document_xml"});
    }
    let text = extract_w_t(&xml);
    json!({"path": path, "format": "docx", "content": text})
}

/// Pull text out of `<w:t>…</w:t>` runs and insert newlines at paragraph ends
/// (`</w:p>`). Deliberately a lightweight scan — no XML dep — good enough to
/// recover the readable body of a Word document.
fn extract_w_t(xml: &str) -> String {
    let mut out = String::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if xml[i..].starts_with("<w:t") {
            // skip to end of opening tag
            if let Some(gt) = xml[i..].find('>') {
                let content_start = i + gt + 1;
                if let Some(close) = xml[content_start..].find("</w:t>") {
                    out.push_str(&xml[content_start..content_start + close]);
                    i = content_start + close + 6;
                    continue;
                }
            }
        }
        if xml[i..].starts_with("</w:p>") {
            out.push('\n');
            i += 6;
            continue;
        }
        // advance one char boundary safely
        let ch_len = xml[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        i += ch_len;
    }
    // decode the handful of XML entities that appear in run text
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn read_pdf(path: &str) -> Value {
    match pdf_extract::extract_text(path) {
        Ok(text) => json!({"path": path, "format": "pdf", "content": text}),
        Err(e) => json!({"path": path, "error": "pdf_extract_failed", "message": e.to_string()}),
    }
}

// ---------------------------------------------------------------------------
// office_write
// ---------------------------------------------------------------------------

pub struct OfficeWrite;

#[async_trait]
impl Tool for OfficeWrite {
    fn name(&self) -> &str { "office_write" }
    fn description(&self) -> &str {
        "Genera un documento de oficina (docx, xlsx, pdf) o texto. Para xlsx usa 'rows' (array de arrays); para docx/pdf/txt usa 'content'."
    }
    fn category(&self) -> ToolCategory { ToolCategory::Base }
    fn parameters(&self) -> ToolSchema {
        let mut props = HashMap::new();
        props.insert("path".into(), json!({"type": "string"}));
        props.insert("content".into(), json!({"type": "string", "description": "Texto (una línea = un párrafo/fila)"}));
        props.insert("rows".into(), json!({"type": "array", "items": {"type": "array", "items": {"type": "string"}}, "description": "Filas para xlsx"}));
        props.insert("title".into(), json!({"type": "string", "default": "Documento"}));
        ToolSchema { schema_type: "object".into(), properties: props, required: Some(vec!["path".into()]) }
    }
    async fn execute(&self, params: Value) -> Result<Value> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("path required"))?
            .to_string();
        let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let title = params.get("title").and_then(|v| v.as_str()).unwrap_or("Documento").to_string();
        let rows: Vec<Vec<String>> = params
            .get("rows")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|r| {
                        r.as_array()
                            .map(|cells| cells.iter().map(|c| cell_to_string(c)).collect())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();

        let out = tokio::task::spawn_blocking(move || write_office(&path, &content, &rows, &title))
            .await
            .map_err(|e| anyhow!("join error: {}", e))?;
        Ok(out)
    }
}

fn cell_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn write_office(path: &str, content: &str, rows: &[Vec<String>], title: &str) -> Value {
    let res = match ext_of(path).as_str() {
        "docx" => write_docx(path, content),
        "xlsx" => write_xlsx(path, content, rows),
        "pdf" => write_pdf(path, content, title),
        _ => std::fs::write(path, content).map(|_| ()).map_err(|e| e.to_string()),
    };
    match res {
        Ok(()) => json!({"path": path, "written": true, "format": ext_of(path)}),
        Err(e) => json!({"path": path, "error": "write_failed", "message": e}),
    }
}

fn write_docx(path: &str, content: &str) -> std::result::Result<(), String> {
    use docx_rs::{Docx, Paragraph, Run};

    let mut docx = Docx::new();
    for line in content.lines() {
        docx = docx.add_paragraph(Paragraph::new().add_run(Run::new().add_text(line)));
    }
    if content.is_empty() {
        docx = docx.add_paragraph(Paragraph::new());
    }
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    docx.build().pack(file).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_xlsx(path: &str, content: &str, rows: &[Vec<String>]) -> std::result::Result<(), String> {
    use rust_xlsxwriter::Workbook;

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();

    // Prefer explicit `rows`; else split `content` into rows (newline) x cells (tab/comma).
    let effective: Vec<Vec<String>> = if !rows.is_empty() {
        rows.to_vec()
    } else {
        content
            .lines()
            .map(|line| {
                let sep = if line.contains('\t') { '\t' } else { ',' };
                line.split(sep).map(|c| c.trim().to_string()).collect()
            })
            .collect()
    };

    for (r, row) in effective.iter().enumerate() {
        for (c, cell) in row.iter().enumerate() {
            ws.write_string(r as u32, c as u16, cell)
                .map_err(|e| e.to_string())?;
        }
    }
    wb.save(path).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_pdf(path: &str, content: &str, title: &str) -> std::result::Result<(), String> {
    use printpdf::{BuiltinFont, Mm, PdfDocument};
    use std::io::BufWriter;

    let (doc, page1, layer1) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer 1");
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| e.to_string())?;

    let mut current_page = page1;
    let mut current_layer = layer1;
    let mut y = 280.0_f32;
    let line_height = 6.0_f32;
    let left = 15.0_f32;

    for line in content.lines() {
        if y < 15.0 {
            let (p, l) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
            current_page = p;
            current_layer = l;
            y = 280.0;
        }
        let layer = doc.get_page(current_page).get_layer(current_layer);
        // printpdf's builtin fonts are WinAnsi; drop chars it can't encode.
        let safe: String = line.chars().filter(|c| c.is_ascii()).collect();
        layer.use_text(safe, 11.0, Mm(left), Mm(y), &font);
        y -= line_height;
    }
    if content.is_empty() {
        let layer = doc.get_page(current_page).get_layer(current_layer);
        layer.use_text(title, 14.0, Mm(left), Mm(y), &font);
    }

    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    doc.save(&mut BufWriter::new(file)).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn create_all() -> Vec<std::sync::Arc<dyn Tool>> {
    vec![
        std::sync::Arc::new(OfficeRead),
        std::sync::Arc::new(OfficeWrite),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_w_t_recovers_paragraph_text() {
        let xml = r#"<w:body><w:p><w:r><w:t>Hola</w:t></w:r><w:r><w:t xml:space="preserve"> mundo</w:t></w:r></w:p><w:p><w:r><w:t>Segunda l&#237;nea</w:t></w:r></w:p></w:body>"#;
        // (numeric entity left as-is; only named entities are decoded)
        let text = extract_w_t(xml);
        assert!(text.contains("Hola mundo"));
        assert!(text.contains('\n'));
    }

    #[tokio::test]
    async fn docx_write_then_read_roundtrip() {
        let path = std::env::temp_dir()
            .join(format!("hc_office_{}.docx", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();

        let body = "Resumen ejecutivo\nHallazgo 1\nRemediacion";
        let w = OfficeWrite
            .execute(json!({"path": path, "content": body}))
            .await
            .unwrap();
        assert_eq!(w["written"], true);

        let r = OfficeRead.execute(json!({"path": path})).await.unwrap();
        assert_eq!(r["format"], "docx");
        let content = r["content"].as_str().unwrap();
        assert!(content.contains("Resumen ejecutivo"));
        assert!(content.contains("Remediacion"));

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn xlsx_write_then_read_roundtrip() {
        let path = std::env::temp_dir()
            .join(format!("hc_office_{}.xlsx", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();

        let w = OfficeWrite
            .execute(json!({"path": path, "rows": [["cve", "sev"], ["CVE-2024-0001", "high"]]}))
            .await
            .unwrap();
        assert_eq!(w["written"], true);

        let r = OfficeRead.execute(json!({"path": path})).await.unwrap();
        assert_eq!(r["format"], "spreadsheet");
        let sheets = r["sheets"].as_array().unwrap();
        assert!(!sheets.is_empty());
        let data = &sheets[0]["data"];
        assert_eq!(data[0][0], "cve");
        assert_eq!(data[1][0], "CVE-2024-0001");

        std::fs::remove_file(&path).ok();
    }
}

#!/usr/bin/env bun
// scoped-browser — servidor MCP (stdio) de navegador SOLO LECTURA para hiveCyber.
//
// Bun.WebView (Chrome/CDP) con el alcance del programa aplicado a CADA petición del
// navegador (incluidas subpeticiones del JavaScript de la página):
//   - Fetch.requestPaused: lo que no esté en la política activa se aborta antes de salir.
//   - Network.setExtraHTTPHeaders: cabeceras obligatorias del programa en todo el tráfico.
//   - Ritmo por host (rate_limit_rps) y tope total de peticiones por sesión.
//   - Sin clic, sin rellenar/enviar formularios, sin evaluate arbitrario: solo lectura.
//   - Si el documento principal responde 403/503 con señales de Cloudflare, se informa y NO se insiste.
// La política se lee del gateway en cada navegación (así sigue la versión activa).
//
// Entorno: HIVECYBER_HOME (gateway.token), HIVECYBER_GATEWAY (def. http://127.0.0.1:18798),
//          BUN_CHROME_PATH o CHROME_PATH, SCOPED_BROWSER_MAX_REQUESTS (def. 150).

import { appendFileSync, readFileSync } from "node:fs";

const GATEWAY = process.env.HIVECYBER_GATEWAY ?? "http://127.0.0.1:18798";
const HOME = process.env.HIVECYBER_HOME ?? `${process.env.HOME}/.hivecyber`;
const MAX_REQ = Number(process.env.SCOPED_BROWSER_MAX_REQUESTS ?? 150);
const CHROME = process.env.BUN_CHROME_PATH ?? process.env.CHROME_PATH;

type Rule = { host: string; methods?: string[]; rate_limit_rps?: number };
type Policy = { program: string; targets: Rule[]; excluded?: string[]; required_headers?: Record<string, string> };

let policyCache: { at: number; p: Policy | null } = { at: 0, p: null };
async function policy(force = false): Promise<Policy | null> {
  if (!force && Date.now() - policyCache.at < 5000) return policyCache.p;
  try {
    const token = readFileSync(`${HOME}/gateway.token`, "utf8").trim();
    const r = await fetch(`${GATEWAY}/api/engagement-policy`, { headers: { Authorization: `Bearer ${token}` } });
    const d: any = await r.json();
    policyCache = { at: Date.now(), p: (d.active?.policy ?? d.policy ?? null) as Policy | null };
  } catch {
    policyCache = { at: Date.now(), p: null };
  }
  return policyCache.p;
}

const hostOf = (u: string) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const matches = (host: string, rule: string) => { const r = rule.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, ""); return host === r || host.endsWith("." + r); };
function ruleFor(p: Policy, url: string): Rule | null {
  const h = hostOf(url);
  if (!h) return null;
  if ((p.excluded ?? []).some((e) => matches(h, e))) return null;
  return p.targets.find((t) => matches(h, t.host) && (!t.methods?.length || t.methods.some((m) => ["GET", "HEAD"].includes(m.toUpperCase())))) ?? null;
}

// ---- estado del navegador ----
let view: Bun.WebView | null = null;
let q: Promise<unknown> = Promise.resolve(); // Bun.WebView admite un solo cdp() pendiente
const cdp = <T,>(m: string, params?: Record<string, unknown>) => { const r = q.then(() => view!.cdp<T>(m, params)); q = r.catch(() => {}); return r; };
const lastAt = new Map<string, number>();
let total = 0, blocked = 0;
let mainStatus: { url: string; status: number; challenge: boolean } | null = null;
let activePolicy: Policy | null = null;
const logFile = `${HOME}/scoped-browser.jsonl`;
const audit = (o: Record<string, unknown>) => { try { appendFileSync(logFile, JSON.stringify({ t: new Date().toISOString(), ...o }) + "\n"); } catch {} };

async function ensureView(p: Policy) {
  if (view) { if (activePolicy?.program !== p.program) await cdp("Network.setExtraHTTPHeaders", { headers: p.required_headers ?? {} }); activePolicy = p; return; }
  view = new Bun.WebView({ backend: { type: "chrome", ...(CHROME ? { path: CHROME } : {}), argv: ["--no-sandbox"] }, width: 1280, height: 800 });
  await view.navigate("about:blank");
  activePolicy = p;
  await cdp("Network.enable");
  await cdp("Network.setExtraHTTPHeaders", { headers: p.required_headers ?? {} });
  await cdp("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
  view.addEventListener("Fetch.requestPaused", async (e: MessageEvent<any>) => {
    const { requestId, request } = e.data;
    const url: string = request.url;
    if (url.startsWith("data:") || url.startsWith("blob:") || url === "about:blank") return void cdp("Fetch.continueRequest", { requestId });
    const pol = (await policy()) ?? null;
    const rule = pol ? ruleFor(pol, url) : null;
    if (!pol || !rule || total >= MAX_REQ || request.method !== "GET") {
      blocked++; audit({ ev: "blocked", url: url.slice(0, 200), why: !rule ? "fuera de alcance" : request.method !== "GET" ? "método" : "tope" });
      return void cdp("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
    }
    const h = hostOf(url), rps = rule.rate_limit_rps ?? 1, gap = 1000 / rps;
    const wait = Math.max(0, (lastAt.get(h) ?? 0) + gap - Date.now());
    lastAt.set(h, Date.now() + wait);
    if (wait) await Bun.sleep(wait);
    total++; audit({ ev: "request", url: url.slice(0, 200) });
    cdp("Fetch.continueRequest", { requestId });
  });
  view.addEventListener("Network.responseReceived", (e: MessageEvent<any>) => {
    const { type, response } = e.data;
    if (type !== "Document") return;
    const hd = Object.fromEntries(Object.entries(response.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
    mainStatus = { url: response.url, status: response.status, challenge: (response.status === 403 || response.status === 503) && (hd["cf-mitigated"] === "challenge" || hd["server"] === "cloudflare") };
  });
}

// ---- herramientas (solo lectura) ----
const ev = (expr: string) => view!.evaluate(expr) as Promise<any>;
const tools: Record<string, { description: string; schema: any; run: (a: any) => Promise<unknown> }> = {
  browser_navigate: {
    description: "Navega (GET) a una URL dentro del alcance del programa activo. Aplica cabeceras obligatorias, ritmo y bloqueo de subpeticiones fuera de alcance. Si Cloudflare devuelve un desafío, lo informa y no insiste.",
    schema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
    run: async ({ url }) => {
      const p = await policy(true);
      if (!p) return { error: "security_policy", message: "sin política activa en el gateway" };
      if (!ruleFor(p, url)) return { error: "security_policy", message: `'${url}' fuera del alcance de '${p.program}'` };
      await ensureView(p);
      mainStatus = null;
      await Promise.race([view!.navigate(url), Bun.sleep(30000)]);
      await Bun.sleep(1500);
      const st = mainStatus as { url: string; status: number; challenge: boolean } | null;
      if (st?.challenge) return { url, status: st.status, challenge: true, message: "Cloudflare bloqueó/desafió la petición. No se intenta evadir; detén las pruebas automáticas en este host." };
      return { url: view!.url, title: view!.title, status: st?.status ?? null, requests_total: total, blocked_out_of_scope: blocked };
    },
  },
  browser_text: {
    description: "Texto visible de la página actual (solo lectura).",
    schema: { type: "object", properties: { max_chars: { type: "number" } } },
    run: async ({ max_chars = 6000 }) => view ? { url: view.url, text: String(await ev("document.body ? document.body.innerText : ''")).slice(0, Math.min(Number(max_chars), 20000)) } : { error: "no hay página; usa browser_navigate" },
  },
  browser_links: {
    description: "Enlaces de la página actual (href y texto), marcando los que quedan en alcance.",
    schema: { type: "object", properties: { limit: { type: "number" } } },
    run: async ({ limit = 80 }) => {
      if (!view) return { error: "no hay página; usa browser_navigate" };
      const p = await policy();
      const links: { text: string; href: string }[] = await ev(`Array.from(document.querySelectorAll('a[href]')).slice(0, ${Math.min(Number(limit), 300)}).map(a=>({text:(a.innerText||'').trim().slice(0,60),href:a.href}))`);
      return links.map((l) => ({ ...l, in_scope: !!(p && ruleFor(p, l.href)) }));
    },
  },
  browser_forms: {
    description: "Lista los formularios (acción, método, campos) SIN rellenarlos ni enviarlos.",
    schema: { type: "object", properties: {} },
    run: async () => view ? ev(`Array.from(document.forms).map(f=>({action:f.action,method:f.method,fields:Array.from(f.elements).map(e=>({name:e.name||e.id,type:e.type||e.tagName.toLowerCase()})).filter(e=>e.name)}))`) : { error: "no hay página; usa browser_navigate" },
  },
  browser_stats: {
    description: "Contadores de la sesión: peticiones permitidas, bloqueadas y tope.",
    schema: { type: "object", properties: {} },
    run: async () => ({ requests_total: total, blocked_out_of_scope: blocked, max_requests: MAX_REQ, program: activePolicy?.program ?? null }),
  },
};

// ---- MCP stdio (JSON-RPC por líneas) ----
const send = (m: unknown) => process.stdout.write(JSON.stringify(m) + "\n");
const text = (r: unknown) => ({ content: [{ type: "text", text: typeof r === "string" ? r : JSON.stringify(r) }] });
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", async (chunk: string) => {
  buf += chunk;
  let i: number;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m: any; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "scoped-browser", version: "0.1.0" } } });
    else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: Object.entries(tools).map(([name, t]) => ({ name, description: t.description, inputSchema: t.schema })) } });
    else if (m.method === "tools/call") {
      const t = tools[m.params?.name];
      if (!t) { send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "tool desconocida" } }); continue; }
      try { send({ jsonrpc: "2.0", id: m.id, result: text(await t.run(m.params?.arguments ?? {})) }); }
      catch (e: any) { send({ jsonrpc: "2.0", id: m.id, result: { ...text({ error: String(e?.message ?? e) }), isError: true } }); }
    } else if (m.id !== undefined && m.method !== undefined) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.on("exit", () => { try { view?.close(); } catch {} });

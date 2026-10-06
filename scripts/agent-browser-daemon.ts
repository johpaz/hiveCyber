// hiveCyber browser backend: persistent Bun.WebView daemon.
//
// Replaces the Vercel `agent-browser` npm CLI with a long-lived Bun process
// that owns the Chrome subprocess and one Bun.WebView per session. Exposed
// over a Unix socket for the /home/jpaez/.local/bin/agent-browser shim.
//
// Protocol: newline-delimited JSON-RPC over /run/user/<uid>/hivecyber-browser.sock
//   Request:  { "id": <number>, "session": <string>, "cmd": <verb>, "args": [<string>...] }
//   Response: { "id": <number>, "ok": <bool>, "data"?: <any>, "error"?: <string>, "message"?: <string> }
//
// Verbs (mirror hiveCyber's web/mod.rs contract):
//   open <url>            -> navigate, returns { url, title }
//   click <css>           -> click selector
//   type <css> <text>     -> click selector then type text
//   screenshot [css?]     -> screenshot (full page or cropped), returns { path }
//   eval <js>             -> evaluate expression in page, returns result
//
// Env:
//   BUN_CHROME_PATH       Chrome/Chromium executable (preferred by Bun.WebView)
//   AGENT_BROWSER_SOCK    Override socket path (default /run/user/$UID/hivecyber-browser.sock)
//   AGENT_BROWSER_IDLE_MS  View idle timeout (default 5 min)
//   BROWSER_DAEMON_PORT   If set, also listen on TCP localhost (for debugging only)

interface RpcReq {
  id: number;
  session: string;
  cmd: string;
  args: string[];
}

interface RpcRes {
  id: number;
  ok: boolean;
  data?: any;
  error?: string;
  message?: string;
}

interface SessionEntry {
  view: any;
  lastUsed: number;
  busy: boolean;
}

const sessions = new Map<string, SessionEntry>();
const IDLE_MS = Number(process.env.AGENT_BROWSER_IDLE_MS ?? 5 * 60 * 1000);
const SOCK_PATH =
  process.env.AGENT_BROWSER_SOCK ??
  `/run/user/${process.getuid?.() ?? 1000}/hivecyber-browser.sock`;
const SCREENSHOT_DIR = process.env.AGENT_BROWSER_SCREENSHOT_DIR ?? "/tmp";

function log(level: string, msg: string): void {
  const ts = new Date().toISOString();
  console.error(`[agent-browser-daemon ${ts}] ${level} ${msg}`);
}

function getSession(name: string): SessionEntry {
  let entry = sessions.get(name);
  if (!entry) {
    log("info", `creating WebView for session "${name}"`);
    const view = new Bun.WebView({
      backend: "chrome",
      width: 1280,
      height: 720,
      headless: true,
    });
    entry = { view, lastUsed: Date.now(), busy: false };
    sessions.set(name, entry);
  }
  entry.lastUsed = Date.now();
  return entry;
}

async function handle(req: RpcReq): Promise<RpcRes> {
  const id = req.id;
  if (!req.session || typeof req.session !== "string") {
    return { id, ok: false, error: "bad_request", message: "session required" };
  }
  if (!Array.isArray(req.args)) {
    return { id, ok: false, error: "bad_request", message: "args must be array" };
  }
  const entry = getSession(req.session);
  if (entry.busy) {
    return {
      id,
      ok: false,
      error: "busy",
      message: `session "${req.session}" already running an operation`,
    };
  }
  entry.busy = true;
  try {
    const v = entry.view;
    const [verb, ...rest] = [req.cmd, ...req.args];
    switch (verb) {
      case "open": {
        const url = rest[0];
        if (!url) return { id, ok: false, error: "bad_request", message: "open <url>" };
        await v.navigate(url);
        return {
          id,
          ok: true,
          data: { url: v.url, title: v.title },
        };
      }
      case "click": {
        const sel = rest[0];
        if (!sel) return { id, ok: false, error: "bad_request", message: "click <selector>" };
        await v.click(sel);
        return { id, ok: true };
      }
      case "type": {
        const [sel, text] = rest;
        if (!sel || text === undefined) {
          return { id, ok: false, error: "bad_request", message: "type <selector> <text>" };
        }
        await v.click(sel);
        await v.type(text);
        return { id, ok: true };
      }
      case "screenshot": {
        const sel = rest[0] || "";
        if (sel && sel.length > 0) {
          // Bun.WebView doesn't crop to a selector natively; emulate by scrolling
          // the element into view before capturing the viewport.
          try { await v.scrollTo(sel, { block: "center" }); } catch { /* ignore */ }
        }
        const buf: Buffer = await v.screenshot({ format: "png", encoding: "buffer" });
        const path = `${SCREENSHOT_DIR}/hcy-${req.session}-${Date.now()}.png`;
        await Bun.write(path, buf);
        return { id, ok: true, data: { path } };
      }
      case "eval": {
        const script = rest.join(" ");
        if (!script) return { id, ok: false, error: "bad_request", message: "eval <script>" };
        const result = await v.evaluate(script);
        return { id, ok: true, data: result };
      }
      case "close": {
        try { v.close(); } catch { /* ignore */ }
        sessions.delete(req.session);
        return { id, ok: true };
      }
      default:
        return { id, ok: false, error: "unknown_command", message: `unknown verb: ${verb}` };
    }
  } catch (e: any) {
    return {
      id,
      ok: false,
      error: "exception",
      message: e?.message ?? String(e),
    };
  } finally {
    entry.busy = false;
  }
}

// Idle reaper — close views that haven't been touched in IDLE_MS.
setInterval(() => {
  const now = Date.now();
  for (const [name, entry] of sessions.entries()) {
    if (entry.busy) continue;
    if (now - entry.lastUsed > IDLE_MS) {
      log("info", `reaping idle session "${name}"`);
      try { entry.view.close(); } catch { /* ignore */ }
      sessions.delete(name);
    }
  }
}, 60_000);

function cleanup(): void {
  log("info", "shutting down");
  for (const [, entry] of sessions) {
    try { entry.view.close(); } catch { /* ignore */ }
  }
  try { Bun.WebView.closeAll(); } catch { /* ignore */ }
  try { Bun.unlinkSync(SOCK_PATH); } catch { /* ignore */ }
  process.exit(0);
}

process.on("SIGTERM", cleanup);
process.on("SIGINT", cleanup);
process.on("exit", () => {
  try { Bun.unlinkSync(SOCK_PATH); } catch { /* ignore */ }
});

// Unix socket server.
try { Bun.unlinkSync(SOCK_PATH); } catch { /* ignore */ }
const server = Bun.listen({
  unix: SOCK_PATH,
  socket: {
    data(socket, data) {
      const text = new TextDecoder().decode(data);
      for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let req: RpcReq;
        try {
          req = JSON.parse(trimmed);
        } catch (e: any) {
          socket.write(
            JSON.stringify({ id: 0, ok: false, error: "parse_error", message: e?.message }) + "\n",
          );
          continue;
        }
        handle(req).then((res) => {
          try { socket.write(JSON.stringify(res) + "\n"); } catch { /* socket gone */ }
        });
      }
    },
    error(_socket, err) {
      log("error", `socket error: ${err?.message ?? err}`);
    },
  },
});

log("info", `agent-browser-daemon listening on ${SOCK_PATH}`);
log("info", `Bun.WebView backend=chrome, idle_timeout=${IDLE_MS}ms`);

// Optional TCP listener for debugging.
const tcpPort = Number(process.env.BROWSER_DAEMON_PORT ?? 0);
if (tcpPort > 0) {
  Bun.serve({
    port: tcpPort,
    hostname: "127.0.0.1",
    async fetch(req) {
      try {
        const body = await req.json();
        const res = await handle(body as RpcReq);
        return Response.json(res);
      } catch (e: any) {
        return Response.json({ ok: false, error: "bad_request", message: e?.message });
      }
    },
  });
  log("info", `TCP debug listener on 127.0.0.1:${tcpPort}`);
}

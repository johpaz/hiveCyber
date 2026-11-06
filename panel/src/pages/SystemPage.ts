import { View, html } from 'rune-ts';
import type { DoctorResp } from '../types';

export interface SystemData {
  doctor: DoctorResp;
  skills: { name: string; category: string; version: string; description: string }[];
  mcp: { name?: string; id?: string; transport?: string; status?: string }[];
}

/** Doctor + skills + MCP, all read-only. */
export class SystemPage extends View<SystemData> {
  override template() {
    const d = this.data.doctor;
    return html`
      <section>
        <h2>Entorno</h2>
        <p>${d.platform} · sandbox del worker:
          <span class="pill ${d.sandbox_available ? 'ok' : 'bad'}">${d.sandbox_available ? 'disponible' : d.allow_unsandboxed ? 'NO (sin confinar, forzado)' : 'no disponible (fail-closed)'}</span>
          · Obscura (navegador MCP): ${d.obscura_mcp ? 'OK' + (d.obscura_path ? ' · ' + d.obscura_path : '') + ' — regístralo con: obscura mcp' : 'ausente'}</p>
        <div class="checks">${d.tools.map((t) => html`<span class="${t.ok ? 'ok' : 'bad'}">${t.ok ? '●' : '○'} ${t.name} <span class="muted">(${t.binary})</span></span>`)}</div>
        <h2>Skills (${this.data.skills.length})</h2>
        <table><thead><tr><th>Skill</th><th>Categoría</th><th>Versión</th><th>Descripción</th></tr></thead>
        <tbody>${this.data.skills.map((s) => html`<tr><td>${s.name}</td><td>${s.category}</td><td>${s.version}</td><td>${s.description}</td></tr>`)}</tbody></table>
        <h2>Servidores MCP (${this.data.mcp.length})</h2>
        ${this.data.mcp.length ? html`<ul>${this.data.mcp.map((m) => html`<li>${m.name ?? m.id} · ${m.transport ?? ''} · ${m.status ?? ''}</li>`)}</ul>` : html`<p class="muted">Ninguno registrado. Las credenciales de MCP nunca se muestran.</p>`}
      </section>
    `;
  }
}

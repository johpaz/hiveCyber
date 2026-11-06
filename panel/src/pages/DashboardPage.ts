import { View, html } from 'rune-ts';
import type { Dashboard } from '../types';

export class DashboardPage extends View<Dashboard> {
  override template() {
    const d = this.data;
    const tile = (label: string, value: unknown, cls = '') =>
      html`<div class="tile ${cls}"><div class="tile-v">${value}</div><div class="tile-l">${label}</div></div>`;
    return html`
      <section>
        <h2>Dashboard</h2>
        <div class="tiles">
          ${tile('Agentes activos', `${d.agents.enabled}/${d.agents.total}`)}
          ${tile('Runs en curso', d.runs.running)}
          ${tile('Runs interrumpidos', d.runs.interrupted, d.runs.interrupted ? 'warn' : '')}
          ${tile('Runs completados', d.runs.completed)}
          ${tile('Audit log', d.audit.verified ? `VERIFIED · ${d.audit.entries}` : `BROKEN · ${d.audit.errors} errores`, d.audit.verified ? 'ok' : 'bad')}
          ${tile('Alcance', d.scope.has_policy ? `${d.scope.program} · ${d.scope.targets} reglas` : 'sin política', d.scope.has_policy ? 'ok' : 'bad')}
        </div>
      </section>
    `;
  }
}

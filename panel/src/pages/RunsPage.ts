import { View, ListView, html } from 'rune-ts';
import type { Run } from '../types';

class RunRowView extends View<Run> {
  override template() {
    const r = this.data;
    const resumable = r.status === 'interrupted' || r.status === 'failed';
    const href = `#/chat?agent=${encodeURIComponent(r.agent_id)}&thread=${encodeURIComponent(r.thread_id)}&resume=1`;
    return html`
      <tr>
        <td class="mono">${r.id.slice(0, 8)}</td><td>${r.agent_id}</td><td>${r.kind}</td>
        <td><span class="pill ${r.status === 'completed' ? 'ok' : r.status === 'running' ? '' : 'bad'}">${r.status}</span></td>
        <td>${r.iterations_used} it · ${r.turns_used} turnos</td>
        <td>${resumable ? html`<a href="${href}">Reanudar</a>` : html``}</td>
      </tr>
    `;
  }
}
class RunListView extends ListView<RunRowView> {
  override tagName = 'tbody';
  ItemView = RunRowView;
}

/** Resume reuses the chat WebSocket, rehydrating history from the thread. */
export class RunsPage extends View<Run[]> {
  private list = new RunListView(this.data);
  override template() {
    return html`
      <section>
        <h2>Runs</h2>
        ${this.data.length ? html`` : html`<p class="muted">Sin runs todavía.</p>`}
        <table><thead><tr><th>Run</th><th>Agente</th><th>Tipo</th><th>Estado</th><th>Uso</th><th></th></tr></thead>${this.list}</table>
      </section>
    `;
  }
}

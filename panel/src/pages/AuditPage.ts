import { View, ListView, html, on } from 'rune-ts';
import { api } from '../api';
import type { AuditEntry } from '../types';

class AuditRowView extends View<AuditEntry> {
  override template() {
    const e = this.data;
    return html`
      <tr>
        <td>${e.timestamp}</td><td>${e.tool}</td><td>${e.target}</td>
        <td>${e.worker}</td><td>${e.operator_id}</td>
        <td class="mono" title="${e.hash_chain_prev}">${e.hash_chain_prev.slice(0, 10)}…</td>
      </tr>
    `;
  }
}
class AuditListView extends ListView<AuditRowView> {
  override tagName = 'tbody';
  ItemView = AuditRowView;
}

/** Strictly read-only: the audit chain has no edit/delete path. */
export class AuditPage extends View<{ entries: AuditEntry[]; verified: boolean; errors: string[] }> {
  private list = new AuditListView(this.data.entries);
  override template() {
    const d = this.data;
    return html`
      <section>
        <h2>Audit log</h2>
        <p>
          <span class="pill ${d.verified ? 'ok' : 'bad'} verdict">${d.verified ? 'VERIFIED' : 'BROKEN'}</span>
          <button class="verify">Re-verificar cadena</button>
        </p>
        <ul class="errors">${d.errors.map((e) => html`<li class="bad">${e}</li>`)}</ul>
        <table><thead><tr><th>Fecha</th><th>Tool</th><th>Target</th><th>Worker</th><th>Operador</th><th>prev hash</th></tr></thead>
        ${this.list}</table>
      </section>
    `;
  }
  @on('click', '.verify')
  private async verify() {
    const r = await api<{ verified: boolean; errors: string[] }>('/audit/verify');
    Object.assign(this.data, { verified: r.verified, errors: r.errors });
    const v = this.element().querySelector('.verdict') as HTMLElement;
    v.textContent = r.verified ? 'VERIFIED' : 'BROKEN';
    v.className = `pill ${r.verified ? 'ok' : 'bad'} verdict`;
    const ul = this.element().querySelector('.errors') as HTMLElement;
    ul.replaceChildren(...r.errors.map((e) => Object.assign(document.createElement('li'), { textContent: e, className: 'bad' })));
  }
}

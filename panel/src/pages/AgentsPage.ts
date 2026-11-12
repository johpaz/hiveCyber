import { View, html, on } from 'rune-ts';
import { api } from '../api';
import type { Agent, ModelInfo } from '../types';
import { toast, type LiveModels } from '../ui';

export interface AgentsData {
  agents: Agent[];
  providers: string[];
  models: ModelInfo[];
  defaultProvider: string;
  live: Record<string, string[]>; // models detected on the provider's own server
}

/**
 * Per-agent provider + model, enable/disable. The server refuses to disable
 * the coordinator.
 *
 * Rows are rendered inline (not via ListView): Rune builds dynamically inserted
 * item views through a <div> parser, which drops bare <tr> elements. Updating
 * means mutating the data and redrawing the page, which re-parses the table whole.
 */
export class AgentsPage extends View<AgentsData> {
  private notice = { text: 'Elige provider y modelo por agente. «default» usa el provider global.', bad: false };
  private detail: Agent | null = null;

  private modelsFor(provider: string | null | undefined): string[] {
    const p = provider || this.data.defaultProvider;
    return this.data.live[p] ?? this.data.models.filter((m) => m.provider_id === p).map((m) => m.model_id);
  }

  private row(a: Agent) {
    const coord = a.role === 'coordinator';
    const opts = this.modelsFor(a.provider_id);
    return html`
      <tr class="clickable" data-id="${a.id}">
        <td><b>${a.name}</b><div class="muted">${a.id} · ${a.role}</div></td>
        <td><span class="pill ${a.enabled ? 'ok' : 'bad'}">${a.enabled ? 'enabled' : 'disabled'}</span></td>
        <td>
          <select class="prov">
            <option value="" ${!a.provider_id ? 'selected' : ''}>default (${this.data.defaultProvider})</option>
            ${this.data.providers.map((p) => html`<option value="${p}" ${a.provider_id === p ? 'selected' : ''}>${p}</option>`)}
          </select>
        </td>
        <td>
          <input class="model" list="dl-${a.id}" placeholder="default del provider" value="${a.model_id ?? ''}" size="26" />
          <datalist id="dl-${a.id}">${opts.map((m) => html`<option value="${m}"></option>`)}</datalist>
        </td>
        <td class="actions">
          <button class="apply primary" type="button">Aplicar</button>
          <button class="toggle" type="button" ${coord ? 'disabled title="El coordinador no se puede deshabilitar"' : ''}>${a.enabled ? 'Deshabilitar' : 'Habilitar'}</button>
        </td>
      </tr>
    `;
  }

  override template() {
    return html`
      <section>
        <h2>Agentes</h2>
        <p class="msg ${this.notice.bad ? 'bad' : 'muted'}">${this.notice.text}</p>
        <div class="card">
          <table>
            <thead><tr><th>Agente</th><th>Estado</th><th>Provider</th><th>Modelo</th><th></th></tr></thead>
            <tbody>${this.data.agents.map((a) => this.row(a))}</tbody>
          </table>
        </div>
        ${this.detail ? html`<h3>Detalle · ${this.detail.id}</h3><pre class="detail">${JSON.stringify(this.detail, null, 2)}</pre>` : html``}
      </section>
    `;
  }

  private agentOf(e: Event): Agent {
    const id = (e.target as HTMLElement).closest('tr')!.dataset.id;
    return this.data.agents.find((a) => a.id === id)!;
  }

  private replace(updated: Agent) {
    const list = this.data.agents;
    list.splice(0, list.length, ...list.map((x) => (x.id === updated.id ? updated : x)));
    if (this.detail?.id === updated.id) this.detail = updated;
  }

  private async run(a: Agent, calls: [string, RequestInit][]) {
    try {
      let updated = a;
      for (const [path, init] of calls) updated = await api<Agent>(`/agents/${a.id}/${path}`, init);
      this.replace(updated);
      this.notice = { text: `${a.id}: actualizado`, bad: false };
      toast(`${a.id}: provider/modelo guardados`);
    } catch (e) {
      this.notice = { text: (e as Error).message, bad: true };
      toast(`${a.id}: ${(e as Error).message}`, true);
    }
    this.redraw();
  }

  @on('click', '.toggle')
  private toggle(e: MouseEvent) {
    const a = this.agentOf(e);
    return this.run(a, [[a.enabled ? 'disable' : 'enable', { method: 'POST' }]]);
  }

  @on('click', '.apply')
  private apply(e: MouseEvent) {
    const tr = (e.target as HTMLElement).closest('tr')!;
    const provider = (tr.querySelector('.prov') as HTMLSelectElement).value;
    const model = (tr.querySelector('.model') as HTMLInputElement).value;
    return this.run(this.agentOf(e), [
      ['provider', { method: 'PUT', body: JSON.stringify({ provider }) }],
      ['model', { method: 'PUT', body: JSON.stringify({ model }) }],
    ]);
  }

  /** Narrow the model suggestions to the chosen provider without a redraw. */
  @on('change', '.prov')
  private async providerChanged(e: Event) {
    const tr = (e.target as HTMLElement).closest('tr')!;
    const provider = (e.target as HTMLSelectElement).value || this.data.defaultProvider;
    const dl = tr.querySelector('datalist')!;
    const fill = () => dl.replaceChildren(...this.modelsFor(provider).map((m) => Object.assign(document.createElement('option'), { value: m })));
    fill();
    (tr.querySelector('.model') as HTMLInputElement).value = '';
    if (!this.data.live[provider]) {
      try {
        // Ask the provider's own server what it really serves; fall back to the catalog silently.
        this.data.live[provider] = (await api<LiveModels>(`/providers/${provider}/live-models`)).models.map((m) => m.id);
        fill();
      } catch { /* provider has no listable endpoint */ }
    }
  }

  @on('click', 'td')
  private show(e: MouseEvent) {
    if ((e.target as HTMLElement).closest('button,input,select')) return;
    this.detail = this.agentOf(e);
    this.redraw();
  }
}

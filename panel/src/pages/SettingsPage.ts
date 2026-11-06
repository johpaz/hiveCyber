import { View, html, on } from 'rune-ts';
import { api } from '../api';
import type { ModelInfo, ProviderInfo, ProvidersResp } from '../types';
import { toast, type LiveModels } from '../ui';

const LOCAL_PRESETS: Record<string, { base_url: string; hint: string }> = {
  hiveagents: { base_url: 'http://127.0.0.1:3000/v1', hint: 'llm-api local de este equipo' },
};

export interface SettingsData { providers: ProvidersResp; models: ModelInfo[]; live: Record<string, string[]> }

/**
 * One card per provider. API keys are write-only: they are sent to the gateway
 * (stored AES-256-GCM encrypted) and never returned — only `key_set` comes back.
 */
export class SettingsPage extends View<SettingsData> {
  private notice = { text: '', bad: false };

  private optionsFor(id: string): string[] {
    return this.data.live[id] ?? this.data.models.filter((m) => m.provider_id === id).map((m) => m.model_id);
  }

  private card(p: ProviderInfo) {
    const preset = LOCAL_PRESETS[p.id];
    return html`
      <article class="card provider ${p.is_default ? 'is-default' : ''}" data-id="${p.id}">
        <header>
          <h3>${p.id}</h3>
          ${p.is_default ? html`<span class="pill ok">default</span>` : html``}
          <span class="pill ${p.key_set ? 'ok' : 'bad'}">${p.key_set ? 'API key guardada' : 'sin API key'}</span>
        </header>
        <label>API key / token <input class="key" type="password" autocomplete="off" placeholder="${p.key_set ? '•••••••• (déjalo vacío para conservarla)' : 'pega aquí la API key'}" /></label>
        <label>Base URL <input class="base" value="${p.base_url ?? ''}" placeholder="(la integrada del provider)" /></label>
        ${preset ? html`<p class="muted">Preset local: ${preset.hint} <button class="preset" type="button">Usar ${preset.base_url}</button></p>` : html``}
        <label>Modelo por defecto <input class="pmodel" list="pm-${p.id}" value="${p.model ?? ''}" />
          <datalist id="pm-${p.id}">${this.optionsFor(p.id).map((m) => html`<option value="${m}"></option>`)}</datalist>
        </label>
        <p class="muted live-count">${this.data.live[p.id] ? `${this.data.live[p.id].length} modelos detectados en el servidor` : 'Modelos: catálogo integrado'}</p>
        ${this.data.live[p.id] ? html`<p class="srv muted">Servidor: <b class="srv-st">…</b> <button class="load" type="button">Cargar el modelo de arriba</button></p>` : html``}
        <footer>
          <button class="save primary" type="button">Guardar</button>
          <button class="detect" type="button">Detectar modelos</button>
          <button class="makedef" type="button" ${p.is_default ? 'disabled' : ''}>Usar como provider por defecto</button>
          <span class="card-msg muted"></span>
        </footer>
      </article>
    `;
  }

  override template() {
    const d = this.data.providers;
    return html`
      <section>
        <h2>Providers de LLM</h2>
        <p class="msg ${this.notice.bad ? 'bad' : 'muted'}">${this.notice.text || `Default actual: ${d.default_provider}${d.default_model ? ' · ' + d.default_model : ''}. Los cambios se aplican al reiniciar el gateway.`}</p>
        <div class="provider-grid">${d.providers.map((p) => this.card(p))}</div>
        <h2>Catálogo de modelos <span class="muted">(${this.data.models.length})</span></h2>
        <input class="filter" placeholder="filtrar por provider o modelo…" />
        <div class="card">
          <table><thead><tr><th>Provider</th><th>Modelo</th><th>Contexto</th><th>USD/1M in</th><th>USD/1M out</th></tr></thead>
          <tbody>${this.data.models.map((m) => html`<tr data-q="${m.provider_id} ${m.model_id}"><td>${m.provider_id}</td><td>${m.model_id}</td><td>${m.context_window}</td><td>${m.input_per_1m}</td><td>${m.output_per_1m}</td></tr>`)}</tbody></table>
        </div>
      </section>
    `;
  }

  private cardOf(e: Event) {
    return (e.target as HTMLElement).closest('article') as HTMLElement;
  }
  private say(text: string, bad = false, card?: HTMLElement) {
    this.notice = { text, bad };
    const m = this.element().querySelector('.msg') as HTMLElement;
    m.textContent = text;
    m.className = `msg ${bad ? 'bad' : 'ok'}`;
    // The page-level note can be scrolled out of view: also show it on the card and as a toast.
    const cm = card?.querySelector('.card-msg') as HTMLElement | null;
    if (cm) Object.assign(cm, { textContent: text, className: `card-msg ${bad ? 'bad' : 'ok'}` });
    toast(text, bad);
  }

  @on('click', '.preset')
  private usePreset(e: MouseEvent) {
    const c = this.cardOf(e);
    (c.querySelector('.base') as HTMLInputElement).value = LOCAL_PRESETS[c.dataset.id!].base_url;
  }

  @on('click', '.save')
  private async save(e: MouseEvent) {
    const c = this.cardOf(e);
    const id = c.dataset.id!;
    const key = c.querySelector<HTMLInputElement>('.key')!;
    const body = {
      api_key: key.value || null,
      base_url: c.querySelector<HTMLInputElement>('.base')!.value || null,
      model: c.querySelector<HTMLInputElement>('.pmodel')!.value || null,
    };
    try {
      await api(`/providers/${id}`, { method: 'PUT', body: JSON.stringify(body) });
      key.value = ''; // never keep the secret in the DOM
      this.say(`${id}: guardado correctamente. Reinicia el gateway para aplicarlo.`, false, c);
      const pill = c.querySelector('header .pill:last-child') as HTMLElement;
      if (body.api_key) Object.assign(pill, { textContent: 'API key guardada', className: 'pill ok' });
    } catch (err) {
      this.say(`${id}: no se pudo guardar — ${(err as Error).message}`, true, c);
    }
  }

  protected override onRender() {
    this.element().querySelectorAll<HTMLElement>('article.provider').forEach((c) => {
      if (c.querySelector('.srv')) void this.refreshServer(c);
    });
  }

  private async refreshServer(c: HTMLElement): Promise<{ loaded: boolean; loading: boolean }> {
    const st = c.querySelector('.srv-st') as HTMLElement;
    try {
      const r = await api<{ loaded: boolean; loading: boolean; model: string | null; error?: string | null }>(`/providers/${c.dataset.id}/server-status`);
      st.textContent = r.loading ? 'cargando modelo…' : r.loaded ? `cargado: ${r.model}` : r.error ? `error: ${r.error}` : 'sin modelo cargado';
      st.className = `srv-st ${r.loaded ? 'ok' : r.error ? 'bad' : ''}`;
      return r;
    } catch {
      st.textContent = 'no responde';
      st.className = 'srv-st bad';
      return { loaded: false, loading: false };
    }
  }

  @on('click', '.load')
  private async load(e: MouseEvent) {
    const c = this.cardOf(e);
    const id = c.dataset.id!;
    const model = c.querySelector<HTMLInputElement>('.pmodel')!.value.trim();
    if (!model) return this.say('Escribe o elige un modelo primero', true, c);
    // llm-api's load is global: it changes what every client of that server uses.
    if (!window.confirm(`Cargar «${model}» en el servidor de ${id}?\nAfecta a TODOS los clientes de ese servidor.`)) return;
    try {
      await api(`/providers/${id}/load-model`, { method: 'POST', body: JSON.stringify({ model }) });
      this.say(`${id}: carga de ${model} solicitada`, false, c);
      for (let i = 0; i < 90; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const r = await this.refreshServer(c);
        if (r.loaded && !r.loading) return this.say(`${id}: modelo listo`, false, c);
      }
    } catch (err) {
      this.say(`${id}: ${(err as Error).message}`, true, c);
    }
  }

  @on('click', '.detect')
  private async detect(e: MouseEvent) {
    const c = this.cardOf(e);
    const id = c.dataset.id!;
    this.say(`${id}: consultando modelos…`, false, c);
    try {
      const r = await api<LiveModels>(`/providers/${id}/live-models`);
      const ids = r.models.map((m) => m.id);
      this.data.live[id] = ids;
      c.querySelector('datalist')!.replaceChildren(...ids.map((m) => Object.assign(document.createElement('option'), { value: m })));
      (c.querySelector('.live-count') as HTMLElement).textContent = `${ids.length} modelos detectados en el servidor`;
      this.say(`${id}: ${ids.length} modelos detectados (${r.source})`, false, c);
    } catch (err) {
      this.say(`${id}: ${(err as Error).message}`, true, c);
    }
  }

  @on('click', '.makedef')
  private async makeDefault(e: MouseEvent) {
    const c = this.cardOf(e);
    try {
      await api('/providers/default', { method: 'PUT', body: JSON.stringify({ id: c.dataset.id, model: c.querySelector<HTMLInputElement>('.pmodel')!.value || null }) });
      this.say(`${c.dataset.id} será el provider por defecto (reinicia el gateway).`, false, c);
    } catch (err) {
      this.say((err as Error).message, true, c);
    }
  }

  @on('input', '.filter')
  private filter(e: Event) {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    this.element().querySelectorAll<HTMLElement>('tr[data-q]').forEach((tr) => {
      tr.hidden = !tr.dataset.q!.toLowerCase().includes(q);
    });
  }
}

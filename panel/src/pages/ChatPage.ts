import { View, html, on } from 'rune-ts';
import { openChat } from '../api';
import type { Agent } from '../types';

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') =>
  Object.assign(document.createElement(tag), { textContent: text, className: cls });

export interface ChatData {
  agents: Agent[];
  blocked: boolean; // no active EngagementPolicy → composer is disabled, not just warned
  resume?: { agent: string; thread: string }; // continue an interrupted run
}

export class ChatPage extends View<ChatData> {
  private ws: WebSocket | null = null;
  private thread = this.data.resume?.thread ?? crypto.randomUUID();
  private rehydrate = !!this.data.resume;
  private bubble: HTMLElement | null = null;
  private agent = this.data.resume?.agent ?? this.data.agents.find((a) => a.role === 'coordinator')?.id ?? this.data.agents[0]?.id ?? 'caelum';

  override template() {
    const d = this.data;
    return html`
      <section class="chat">
        <h2>Chat en vivo</h2>
        <p>
          <label>Agente
            <select class="agent">${d.agents.filter((a) => a.enabled).map((a) => html`<option value="${a.id}" ${a.id === this.agent ? 'selected' : ''}>${a.name} (${a.role})</option>`)}</select>
          </label>
          <span class="conn muted">desconectado</span>
        </p>
        ${d.blocked ? html`<p class="bad">Sin EngagementPolicy activa: el chat está bloqueado. Activa una en «Alcance».</p>` : html``}
        <div class="log"></div>
        <div class="composer">
          <textarea rows="2" class="msg" placeholder="Mensaje para el agente (Enter envía, Shift+Enter nueva línea)" ${d.blocked ? 'disabled' : ''}></textarea>
          <button class="send primary" type="button" ${d.blocked ? 'disabled' : ''}>Enviar</button>
        </div>
      </section>
    `;
  }

  protected override onRender() {
    if (!this.data.blocked) void this.connect();
  }

  dispose() {
    this.ws?.close();
    this.ws = null;
  }

  private log() {
    return this.element().querySelector('.log') as HTMLElement;
  }
  private push(node: HTMLElement) {
    const log = this.log();
    log.append(node);
    log.scrollTop = log.scrollHeight;
  }
  private status(t: string) {
    (this.element().querySelector('.conn') as HTMLElement).textContent = t;
  }

  private async connect() {
    this.dispose();
    this.status('conectando…');
    try {
      const ws = await openChat(this.agent, this.thread, this.rehydrate);
      this.rehydrate = false; // only the first connection rebuilds history
      this.ws = ws;
      ws.onopen = () => this.status('conectado');
      ws.onclose = () => this.status('desconectado');
      ws.onmessage = (m) => this.onChunk(JSON.parse(m.data));
    } catch (e) {
      this.status('error: ' + (e as Error).message);
    }
  }

  // Everything below renders via textContent — model/tool output is never injected as HTML.
  private onChunk(c: any) {
    switch (c.type) {
      case 'Agent':
        if (!this.bubble) this.push((this.bubble = el('div', '', 'msg-agent')));
        this.bubble.textContent += c.text;
        break;
      case 'Done':
        if (!this.bubble && c.final_text) this.push(el('div', c.final_text, 'msg-agent'));
        this.bubble = null;
        break;
      case 'Reasoning':
        this.push(el('div', c.text, 'msg-reason'));
        break;
      case 'ToolCall':
        this.bubble = null;
        this.push(el('div', `▶ ${c.name}(${JSON.stringify(c.args)})`, 'msg-tool'));
        break;
      case 'ToolResult':
        this.push(el('div', `◀ ${c.name}: ${JSON.stringify(c.result).slice(0, 2000)}`, 'msg-tool'));
        break;
      case 'Usage':
        this.push(el('div', `tokens in=${c.input_tokens} out=${c.output_tokens}`, 'muted'));
        break;
      case 'ApprovalRequired':
        this.bubble = null;
        this.push(this.approvalCard(c));
        break;
      case 'Error':
        this.push(el('div', c.message, 'bad'));
        break;
    }
  }

  /** One card per blocked call, showing the exact category + arguments. Single use. */
  private approvalCard(c: { category: string; tool: string; args: unknown }) {
    const card = el('div', '', 'approval');
    card.append(
      el('b', `Aprobación humana requerida — ${c.category}`),
      el('pre', `${c.tool}(${JSON.stringify(c.args, null, 2)})`),
    );
    const decide = (type: 'approve' | 'deny') => {
      this.ws?.send(JSON.stringify({ type, category: c.category }));
      card.replaceChildren(el('b', `${type === 'approve' ? 'Aprobado' : 'Denegado'}: ${c.category} → ${c.tool}`, type === 'approve' ? 'ok' : 'bad'));
    };
    const yes = Object.assign(el('button', 'Aprobar', 'primary'), { type: 'button' });
    const no = Object.assign(el('button', 'Denegar'), { type: 'button' });
    yes.onclick = () => decide('approve');
    no.onclick = () => decide('deny');
    card.append(yes, no);
    return card;
  }

  private send() {
    const ta = this.element().querySelector('.msg') as HTMLTextAreaElement;
    const text = ta.value.trim();
    if (!text || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.push(el('div', text, 'msg-user'));
    this.bubble = null;
    this.ws.send(JSON.stringify({ type: 'user_message', text }));
    ta.value = '';
  }

  @on('click', '.send')
  private onSend() {
    this.send();
  }
  @on('keydown', '.msg')
  private onKey(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      this.send();
    }
  }
  @on('change', '.agent')
  private onAgent(e: Event) {
    this.agent = (e.target as HTMLSelectElement).value;
    this.thread = crypto.randomUUID();
    this.rehydrate = false;
    this.log().replaceChildren();
    void this.connect();
  }
}

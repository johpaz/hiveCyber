import { View, ListView, html, on } from 'rune-ts';
import { api } from '../api';
import { APPROVAL, PROHIBITED, type Policy, type PolicyVersion, type TargetRule } from '../types';

const csv = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', cls = '') =>
  Object.assign(document.createElement(tag), { textContent: text, className: cls });

class TargetRowView extends View<TargetRule> {
  override template() {
    const t = this.data;
    return html`
      <div class="row">
        <input class="host" placeholder="host / dominio / CIDR" value="${t.host}" />
        <input class="paths" placeholder="paths (csv, ej. /api/**)" value="${t.paths.join(', ')}" />
        <input class="methods" placeholder="métodos (csv)" value="${t.methods.join(', ')}" />
        <input class="rps" type="number" min="0" step="0.1" placeholder="req/s" value="${t.rate_limit_rps ?? ''}" />
        <label><input class="own" type="checkbox" ${t.only_own_accounts ? 'checked' : ''} /> solo cuentas propias</label>
        <button class="rm" type="button">✕</button>
      </div>
    `;
  }
  read(): TargetRule {
    const q = (s: string) => this.element().querySelector(s) as HTMLInputElement;
    const rps = q('.rps').value;
    return {
      host: q('.host').value.trim(),
      paths: csv(q('.paths').value),
      methods: csv(q('.methods').value).map((m) => m.toUpperCase()),
      rate_limit_rps: rps === '' ? null : Number(rps),
      only_own_accounts: q('.own').checked,
    };
  }
}
class TargetListView extends ListView<TargetRowView> {
  ItemView = TargetRowView;
}

export interface PolicyPageData {
  active: PolicyVersion | null;
  draft: PolicyVersion | null;
}

/** Control central: Save draft → review diff → Activate (two separate, audited steps). */
export class PolicyPage extends View<PolicyPageData> {
  private base: Policy = this.pickBase();
  private targets = new TargetListView(this.base.targets);

  private pickBase(): Policy {
    const { active, draft } = this.data;
    if (draft && (!active || draft.version > active.version)) return draft.policy;
    if (active) return active.policy;
    // No policy yet: every prohibition starts ON (deny by default).
    return { program: '', targets: [], excluded: [], prohibited: [...PROHIBITED], require_human_approval: ['exploit', 'credential_use'] };
  }

  override template() {
    const b = this.base;
    const tw = b.time_windows;
    const a = this.data.active;
    return html`
      <section class="policy">
        <h2>Alcance autorizado (EngagementPolicy)</h2>
        <p class="muted">${a ? `Activa: v${a.version} · ${a.policy.program}` : 'No hay política activa.'} Guardar crea un borrador; no cambia lo que pueden tocar los agentes hasta activarlo.</p>
        <label>Programa <input class="program" value="${b.program}" placeholder="ej. acme-bugcrowd" /></label>

        <h3>Targets en alcance</h3>
        ${this.targets}
        <button class="add" type="button">+ Añadir regla</button>

        <h3>Exclusiones (una por línea)</h3>
        <textarea class="excluded" rows="3">${b.excluded.join('\n')}</textarea>

        <h3>Actividades prohibidas</h3>
        <div class="checks">
          ${PROHIBITED.map((p) => html`<label><input type="checkbox" class="prohibited" data-name="${p}" ${b.prohibited.includes(p) ? 'checked' : ''} /> ${p}</label>`)}
        </div>

        <h3>Requieren aprobación humana</h3>
        <div class="checks">
          ${APPROVAL.map((p) => html`<label><input type="checkbox" class="approval" data-name="${p}" ${b.require_human_approval.includes(p) ? 'checked' : ''} /> ${p}</label>`)}
        </div>

        <h3>Ventana horaria (UTC, opcional)</h3>
        <div class="row">
          <input class="days" placeholder="días (csv: Mon, Tue…)" value="${tw?.allowed_days.join(', ') ?? ''}" />
          <input class="h0" type="number" min="0" max="23" placeholder="desde" value="${tw?.allowed_hours_utc?.[0] ?? ''}" />
          <input class="h1" type="number" min="0" max="23" placeholder="hasta" value="${tw?.allowed_hours_utc?.[1] ?? ''}" />
        </div>

        <h3>Justificación</h3>
        <textarea class="justification" rows="2" placeholder="Obligatoria si levantas una prohibición o quitas una aprobación humana"></textarea>

        <p><button class="save primary" type="button">Guardar borrador</button></p>
        <div class="result"></div>
      </section>
    `;
  }

  private q<T extends HTMLElement>(s: string) {
    return this.element().querySelector(s) as T;
  }
  private checked(cls: string) {
    return [...this.element().querySelectorAll<HTMLInputElement>(`input.${cls}`)].filter((i) => i.checked).map((i) => i.dataset.name!);
  }

  private collect(): Policy {
    const days = csv(this.q<HTMLInputElement>('.days').value);
    const h0 = this.q<HTMLInputElement>('.h0').value;
    const h1 = this.q<HTMLInputElement>('.h1').value;
    const hasWindow = days.length > 0 || (h0 !== '' && h1 !== '');
    return {
      program: this.q<HTMLInputElement>('.program').value.trim(),
      targets: this.targets.itemViews.map((v) => v.read()).filter((t) => t.host),
      excluded: lines(this.q<HTMLTextAreaElement>('.excluded').value),
      prohibited: this.checked('prohibited'),
      require_human_approval: this.checked('approval'),
      time_windows: hasWindow
        ? { allowed_days: days, allowed_hours_utc: h0 !== '' && h1 !== '' ? [Number(h0), Number(h1)] : null }
        : null,
    };
  }

  @on('click', '.add')
  private addRow() {
    this.targets.append({ host: '', paths: ['/**'], methods: ['GET'], rate_limit_rps: null, only_own_accounts: false });
  }

  @on('click', '.rm')
  private removeRow(e: MouseEvent) {
    const row = (e.target as HTMLElement).closest('.row');
    const iv = this.targets.itemViews.find((v) => v.element().contains(row));
    if (iv) this.targets.removeByItemView(iv);
  }

  @on('click', '.save')
  private async save() {
    const result = this.q<HTMLElement>('.result');
    const policy = this.collect();
    const cur = this.data.active?.policy;
    // Loosening = lifting a prohibition or dropping a human-approval requirement.
    const loosened = cur
      ? [...cur.prohibited.filter((p) => !policy.prohibited.includes(p)), ...cur.require_human_approval.filter((p) => !policy.require_human_approval.includes(p))]
      : [];
    const justification = this.q<HTMLTextAreaElement>('.justification').value.trim();
    if (loosened.length) {
      if (!justification) return result.replaceChildren(el('p', 'Escribe una justificación para relajar: ' + loosened.join(', '), 'bad'));
      for (const name of loosened) {
        if (window.prompt(`Vas a RELAJAR un control. Escribe exactamente "${name}" para confirmar:`) !== name) {
          return result.replaceChildren(el('p', 'Cancelado: confirmación no coincide.', 'bad'));
        }
      }
    }
    try {
      const doc = await api<PolicyVersion>('/engagement-policy', {
        method: 'PUT',
        body: JSON.stringify({ policy, justification: justification || null }),
      });
      this.showDiff(doc, result);
    } catch (e) {
      result.replaceChildren(el('p', (e as Error).message, 'bad'));
    }
  }

  private showDiff(doc: PolicyVersion, out: HTMLElement) {
    const cur = this.data.active?.policy;
    const next = doc.policy;
    const hosts = (p?: Policy) => new Set((p?.targets ?? []).map((t) => t.host));
    const added = [...hosts(next)].filter((h) => !hosts(cur).has(h));
    const removed = [...hosts(cur)].filter((h) => !hosts(next).has(h));
    const box = el('div', '', 'diff');
    box.append(el('h3', `Borrador v${doc.version} guardado — revisa antes de activar`));
    const add = (label: string, items: string[], cls: string) =>
      items.length && box.append(el('p', `${label}: ${items.join(', ')}`, cls));
    add('➕ Hosts NUEVOS en alcance', added, 'bad');
    add('➖ Hosts quitados', removed, 'ok');
    add('⚠ Prohibiciones levantadas', doc.lifted_prohibitions ?? [], 'bad');
    if (!added.length && !removed.length && !(doc.lifted_prohibitions ?? []).length) box.append(el('p', 'Sin cambios de hosts ni de prohibiciones.', 'muted'));

    const label = el('label');
    const chk = Object.assign(document.createElement('input'), { type: 'checkbox' });
    label.append(chk, ' Confirmo que este alcance está autorizado por el programa');
    const btn = Object.assign(el('button', `Activar v${doc.version}`, 'primary'), { type: 'button', disabled: true });
    chk.addEventListener('change', () => (btn.disabled = !chk.checked));
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        await api(`/engagement-policy/${doc.version}/activate`, { method: 'POST' });
        window.dispatchEvent(new Event('hc:scope-changed'));
        out.replaceChildren(el('p', `v${doc.version} activada y auditada. Los agentes ya operan con este alcance.`, 'ok'));
      } catch (e) {
        out.append(el('p', (e as Error).message, 'bad'));
      }
    });
    box.append(label, btn);
    out.replaceChildren(box);
  }
}

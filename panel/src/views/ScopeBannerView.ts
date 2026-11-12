import { View, html } from 'rune-ts';
import type { SecurityStatus } from '../types';

/** Always mounted: the active scope is never out of sight. */
export class ScopeBannerView extends View<{ status: SecurityStatus | null }> {
  override template() {
    const s = this.data.status;
    if (!s) return html`<div class="banner banner-warn">Conectando con el gateway…</div>`;
    return html`
      <div class="banner ${s.has_policy ? 'banner-ok' : 'banner-warn'}">
        <span><b>Alcance:</b> ${s.has_policy ? `${s.program} · v${s.active_policy_version}` : 'SIN política activa — el chat está bloqueado'}</span>
        <span><b>Aprobación humana:</b> ${(s.require_human_approval ?? []).join(', ') || '—'}</span>
        ${s.window ? html`<span class="${s.window.open_now ? '' : 'banner-danger'}"><b>Ventana:</b> ${s.window.open_now ? 'ABIERTA' : 'CERRADA'}${s.window.allowed_hours_utc ? ` · ${String(s.window.allowed_hours_utc[0]).padStart(2, '0')}:00–${String(s.window.allowed_hours_utc[1]).padStart(2, '0')}:00 UTC` : ''}</span>` : html``}
        ${s.required_headers?.length ? html`<span class="muted">cabeceras: ${s.required_headers.join(', ')}</span>` : html``}
        ${s.unsafe_mode ? html`<span class="banner-danger">UNSAFE MODE</span>` : html`<span class="muted">safe mode</span>`}
        ${s.allow_cli_exec ? html`<span class="banner-danger">cli_exec ON</span>` : html``}
      </div>
    `;
  }
  update(status: SecurityStatus | null) {
    this.data.status = status;
    this.redraw();
  }
}

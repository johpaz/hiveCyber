import { View, html, on } from 'rune-ts';
import { api, getToken, setToken } from './api';
import './styles.css';
import { AgentsPage } from './pages/AgentsPage';
import { AuditPage } from './pages/AuditPage';
import { ChatPage } from './pages/ChatPage';
import { DashboardPage } from './pages/DashboardPage';
import { PolicyPage } from './pages/PolicyPage';
import { RunsPage } from './pages/RunsPage';
import { SettingsPage } from './pages/SettingsPage';
import { SystemPage, type SystemData } from './pages/SystemPage';
import { ScopeBannerView } from './views/ScopeBannerView';
import type { LiveModels } from './ui';
import type { Activity, Agent, AuditEntry, Dashboard, ModelInfo, PolicyVersion, ProvidersResp, Run, SecurityStatus } from './types';

class LoginView extends View<{ error: string }> {
  override template() {
    return html`
      <form class="login">
        <h1 class="brand-h">HiveCyber</h1>
        <p class="muted">Pega el token que imprimió <code>hivecyber-gateway</code> (también en <code>$HIVECYBER_HOME/gateway.token</code>).</p>
        <input class="token" type="password" placeholder="token" autofocus />
        <button class="primary" type="submit">Entrar</button>
        <p class="bad">${this.data.error}</p>
      </form>
    `;
  }
  @on('submit')
  private submit(e: Event) {
    e.preventDefault();
    const v = (this.element().querySelector('.token') as HTMLInputElement).value;
    if (v.trim()) {
      setToken(v);
      location.reload();
    }
  }
}

const ROUTES = ['dashboard', 'colmena', 'alcance', 'chat', 'agentes', 'runs', 'audit', 'ajustes', 'sistema'] as const;
const LABELS: Record<string, string> = { dashboard: 'Dashboard', colmena: 'Colmena 3D', alcance: 'Alcance', chat: 'Chat', agentes: 'Agentes', runs: 'Runs', audit: 'Audit', ajustes: 'Providers', sistema: 'Sistema' };

class Shell {
  banner = new ScopeBannerView({ status: null });
  nav = document.createElement('nav');
  main = document.createElement('main');
  current: { dispose?: () => void } | null = null;
  params = new URLSearchParams();

  mount(root: HTMLElement) {
    root.replaceChildren(this.banner.render(), this.nav, this.main);
    window.addEventListener('hashchange', () => void this.route());
    window.addEventListener('hc:scope-changed', () => void this.refreshBanner());
    void this.refreshBanner();
    void this.route();
  }

  async refreshBanner() {
    try {
      this.banner.update(await api<SecurityStatus>('/security/status'));
    } catch {
      this.banner.update(null);
    }
  }

  async route() {
    const [rawName, qs] = (location.hash.replace('#/', '') || 'dashboard').split('?');
    const name = rawName as (typeof ROUTES)[number];
    this.params = new URLSearchParams(qs ?? '');
    this.nav.replaceChildren(
      Object.assign(document.createElement('span'), { className: 'brand', textContent: 'HiveCyber' }),
      ...ROUTES.map((r) => Object.assign(document.createElement('a'), { href: `#/${r}`, textContent: LABELS[r], className: r === name ? 'active' : '' })),
    );
    this.current?.dispose?.();
    this.current = null;
    try {
      const page = await this.build(name);
      this.main.replaceChildren(page.render());
    } catch (e) {
      this.main.replaceChildren(Object.assign(document.createElement('p'), { className: 'bad', textContent: (e as Error).message }));
    }
  }

  /** Models actually served by the local llm-api (empty if unreachable). */
  private async liveModels(): Promise<Record<string, string[]>> {
    try {
      return { hiveagents: (await api<LiveModels>('/providers/hiveagents/live-models')).models.map((m) => m.id) };
    } catch {
      return {};
    }
  }

  private async build(name: string): Promise<View<any>> {
    switch (name) {
      case 'alcance':
        return new PolicyPage(await api<{ active: PolicyVersion | null; latest_draft: PolicyVersion | null }>('/engagement-policy').then((r) => ({ active: r.active, draft: r.latest_draft })));
      case 'chat': {
        const [agents, st] = await Promise.all([api<Agent[]>('/agents'), api<SecurityStatus>('/security/status')]);
        const agent = this.params.get('agent');
        const thread = this.params.get('thread');
        const resume = this.params.get('resume') && agent && thread ? { agent, thread } : undefined;
        const page = new ChatPage({ agents, blocked: !st.has_policy, resume });
        this.current = page;
        return page;
      }
      case 'colmena': {
        const { HivePage } = await import('./pages/HivePage'); // lazy: keeps three.js out of the initial bundle
        const page = new HivePage(await api<Activity>('/activity'));
        this.current = page;
        return page;
      }
      case 'agentes': {
        const [agents, prov, models] = await Promise.all([api<Agent[]>('/agents'), api<ProvidersResp>('/providers'), api<ModelInfo[]>('/models')]);
        return new AgentsPage({ agents, providers: prov.providers.map((p) => p.id), models, defaultProvider: prov.default_provider, live: await this.liveModels() });
      }
      case 'runs':
        return new RunsPage(await api<Run[]>('/runs'));
      case 'ajustes': {
        const [providers, models] = await Promise.all([api<ProvidersResp>('/providers'), api<ModelInfo[]>('/models')]);
        return new SettingsPage({ providers, models, live: await this.liveModels() });
      }
      case 'sistema': {
        const [doctor, skills, mcp] = await Promise.all([api<SystemData['doctor']>('/doctor'), api<SystemData['skills']>('/skills'), api<SystemData['mcp']>('/mcp')]);
        return new SystemPage({ doctor, skills, mcp });
      }
      case 'audit': {
        const [entries, v] = await Promise.all([api<AuditEntry[]>('/audit?limit=200'), api<{ verified: boolean; errors: string[] }>('/audit/verify')]);
        return new AuditPage({ entries, verified: v.verified, errors: v.errors });
      }
      default:
        return new DashboardPage(await api<Dashboard>('/dashboard/summary'));
    }
  }
}

const root = document.getElementById('app')!;
if (!getToken()) {
  root.append(new LoginView({ error: '' }).render());
} else {
  new Shell().mount(root);
}
window.addEventListener('hc:unauth', () => location.reload());

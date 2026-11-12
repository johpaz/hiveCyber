import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';
import { View, html, on } from 'rune-ts';
import { api } from '../api';
import type { Activity, ActivityTask } from '../types';

const COLORS: Record<string, number> = {
  caelum: 0xffd166, recon_operator: 0x4cc9f0, vuln_scanner: 0xf9c74f, exploit_operator: 0xf94144,
  forensics_analyst: 0xb388ff, web_pentester: 0x80ed99, threat_intel_analyst: 0x4895ef,
  report_writer: 0xff7eb6, workspace_file_operator: 0x9aa5b1,
};
const SIM_TOOLS = ['nmap', 'dig', 'whois', 'nuclei', 'nikto', 'semgrep', 'trivy', 'web_fetch', 'yara', 'fs_read'];

interface Node3D {
  id: string; name: string; color: number; pos: THREE.Vector3;
  mesh: THREE.Mesh; mat: THREE.MeshStandardMaterial; halo: THREE.Mesh;
  working: boolean; energy: number; flash: number; label: THREE.Sprite;
}
interface Packet { mesh: THREE.Mesh; from: THREE.Vector3; to: THREE.Vector3; t: number; speed: number; bounce: boolean }
interface Floater { sprite: THREE.Sprite; life: number }

function labelSprite(text: string, color: string, px = 64): THREE.Sprite {
  const c = document.createElement('canvas');
  const ctx = c.getContext('2d')!;
  ctx.font = `600 ${px}px system-ui, sans-serif`;
  const w = Math.ceil(ctx.measureText(text).width) + 24;
  c.width = w; c.height = px + 24;
  ctx.font = `600 ${px}px system-ui, sans-serif`;
  ctx.fillStyle = color; ctx.textBaseline = 'middle'; ctx.fillText(text, 12, c.height / 2);
  const tex = new THREE.CanvasTexture(c);
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false }));
  sp.scale.set((c.width / c.height) * 0.42, 0.42, 1);
  return sp;
}

/**
 * 3D view of the swarm: the coordinator at the centre, workers on a ring.
 * Delegations travel along the edges, tool calls flash a node and float a label.
 * Fed by GET /api/activity (polled); a clearly-labelled simulation drives the
 * same ingest path so the view can be seen without a running model.
 */
export class HivePage extends View<Activity> {
  private renderer!: THREE.WebGLRenderer;
  private composer!: EffectComposer;
  private scene = new THREE.Scene();
  private camera = new THREE.PerspectiveCamera(50, 1, 0.1, 200);
  private controls!: OrbitControls;
  private nodes = new Map<string, Node3D>();
  private packets: Packet[] = [];
  private floaters: Floater[] = [];
  private stars!: THREE.Points;
  private raf = 0;
  private poll = 0;
  private ro?: ResizeObserver;
  private last = performance.now();
  private elapsed = 0;
  private primed = false;
  private taskState = new Map<string, string>();
  private seenTrace = new Set<string>();
  private simTimers: number[] = [];
  private simulating = false;

  override template() {
    return html`
      <section class="hive">
        <div class="hive-head">
          <h2>Colmena 3D</h2>
          <span class="muted hive-sub">Arrastra para rotar · rueda para zoom · los nodos brillan cuando un agente trabaja</span>
          <button class="sim" type="button">▶ Simular actividad</button>
        </div>
        <div class="hive-grid">
          <div class="hive-stage"><canvas></canvas><span class="sim-badge" hidden>SIMULACIÓN</span></div>
          <aside class="hive-side">
            <h3>Agentes</h3>
            <ul class="legend">${this.data.agents.map((a) => html`<li data-id="${a.id}"><i style="background:#${(COLORS[a.id] ?? 0x9aa5b1).toString(16).padStart(6, '0')}"></i>${a.name ?? a.id}<b class="st"></b></li>`)}</ul>
            <h3>Eventos en vivo</h3>
            <ol class="feed"></ol>
          </aside>
        </div>
      </section>
    `;
  }

  protected override onRender() {
    this.initScene();
    void this.refresh();
    this.poll = window.setInterval(() => void this.refresh(), 1200);
  }

  dispose() {
    cancelAnimationFrame(this.raf);
    clearInterval(this.poll);
    this.simTimers.forEach(clearTimeout);
    this.ro?.disconnect();
    this.renderer?.dispose();
    this.scene.traverse((o) => {
      const m = o as THREE.Mesh;
      m.geometry?.dispose?.();
    });
  }

  // ---- scene -------------------------------------------------------------------

  private initScene() {
    const stage = this.element().querySelector('.hive-stage') as HTMLElement;
    const canvas = stage.querySelector('canvas') as HTMLCanvasElement;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.scene.fog = new THREE.FogExp2(0x070b12, 0.022);
    this.camera.position.set(0, 9, 17);

    this.scene.add(new THREE.AmbientLight(0x6677aa, 0.7));
    const key = new THREE.PointLight(0xffffff, 60, 60);
    key.position.set(0, 10, 4);
    this.scene.add(key);

    // Star field
    const g = new THREE.BufferGeometry();
    const n = 1400, pos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const r = 30 + Math.random() * 60, th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos.set([r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.6, r * Math.sin(ph) * Math.sin(th)], i * 3);
    }
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    this.stars = new THREE.Points(g, new THREE.PointsMaterial({ color: 0x88aaff, size: 0.12, transparent: true, opacity: 0.7, depthWrite: false }));
    this.scene.add(this.stars);

    // Floor grid
    const grid = new THREE.GridHelper(60, 60, 0x1b2a44, 0x101a2b);
    grid.position.y = -3.2;
    (grid.material as THREE.Material).transparent = true;
    (grid.material as THREE.Material).opacity = 0.5;
    this.scene.add(grid);

    this.buildNodes();

    this.controls = new OrbitControls(this.camera, canvas);
    this.controls.enableDamping = true;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 0.5;
    this.controls.maxPolarAngle = Math.PI * 0.62;
    this.controls.minDistance = 8;
    this.controls.maxDistance = 40;
    this.controls.addEventListener('start', () => (this.controls.autoRotate = false));

    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));
    this.composer.addPass(new UnrealBloomPass(new THREE.Vector2(256, 256), 0.6, 0.45, 0.62));
    this.composer.addPass(new OutputPass());

    const resize = () => {
      const w = stage.clientWidth || 800, h = stage.clientHeight || 520;
      this.renderer.setSize(w, h, false);
      this.composer.setSize(w, h);
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
    };
    this.ro = new ResizeObserver(resize);
    this.ro.observe(stage);
    resize();
    this.loop();
  }

  private buildNodes() {
    const agents = this.data.agents;
    const coord = agents.find((a) => a.role === 'coordinator') ?? agents[0];
    const workers = agents.filter((a) => a !== coord);
    const mk = (id: string, name: string, pos: THREE.Vector3, big: boolean) => {
      const color = COLORS[id] ?? 0x9aa5b1;
      const geo = big ? new THREE.IcosahedronGeometry(1.5, 1) : new THREE.CylinderGeometry(0.95, 0.95, 0.5, 6);
      const mat = new THREE.MeshStandardMaterial({ color: 0x0b1220, emissive: color, emissiveIntensity: 0.5, metalness: 0.6, roughness: 0.3, flatShading: true });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      const halo = new THREE.Mesh(new THREE.RingGeometry(big ? 2.0 : 1.35, big ? 2.1 : 1.42, 64), new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.35, side: THREE.DoubleSide, depthWrite: false }));
      halo.position.copy(pos);
      halo.rotation.x = -Math.PI / 2;
      const label = labelSprite(name, '#' + color.toString(16).padStart(6, '0'));
      label.position.copy(pos).add(new THREE.Vector3(0, big ? 2.7 : 1.5, 0));
      this.scene.add(mesh, halo, label);
      this.nodes.set(id, { id, name, color, pos, mesh, mat, halo, working: false, energy: 0.15, flash: 0, label });
    };
    if (coord) mk(coord.id, coord.name ?? coord.id, new THREE.Vector3(0, 0, 0), true);
    workers.forEach((w, i) => {
      const a = (i / Math.max(workers.length, 1)) * Math.PI * 2;
      const p = new THREE.Vector3(Math.cos(a) * 7.5, Math.sin(i * 1.7) * 0.8, Math.sin(a) * 7.5);
      mk(w.id, w.name ?? w.id, p, false);
      if (coord) {
        const line = new THREE.Line(
          new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0), p]),
          new THREE.LineBasicMaterial({ color: COLORS[w.id] ?? 0x9aa5b1, transparent: true, opacity: 0.22 }),
        );
        this.scene.add(line);
      }
    });
  }

  private loop = () => {
    this.raf = requestAnimationFrame(this.loop);
    const now = performance.now();
    const dt = Math.min((now - this.last) / 1000, 0.05);
    this.last = now;
    this.elapsed += dt;
    const t = this.elapsed;

    for (const n of this.nodes.values()) {
      const target = n.working ? 1 : 0.15;
      n.energy += (target - n.energy) * Math.min(1, dt * 4);
      n.flash = Math.max(0, n.flash - dt * 2.2);
      n.mat.emissiveIntensity = 0.45 + n.energy * 2.0 + n.flash * 3.5;
      n.mesh.rotation.y += dt * (0.3 + n.energy * 1.6);
      const breathe = 1 + Math.sin(t * 2 + n.pos.x) * 0.03 + n.flash * 0.18;
      n.mesh.scale.setScalar(breathe);
      (n.halo.material as THREE.MeshBasicMaterial).opacity = 0.2 + n.energy * 0.5;
      n.halo.scale.setScalar(1 + Math.sin(t * 3 + n.pos.z) * 0.04 + n.energy * 0.12);
      n.mesh.position.y = n.pos.y + Math.sin(t * 1.2 + n.pos.x) * 0.12;
    }

    for (let i = this.packets.length - 1; i >= 0; i--) {
      const p = this.packets[i];
      p.t += dt * p.speed;
      const k = Math.min(p.t, 1);
      p.mesh.position.lerpVectors(p.from, p.to, k);
      p.mesh.position.y += Math.sin(Math.PI * k) * 1.3;
      p.mesh.scale.setScalar(0.6 + Math.sin(Math.PI * k) * 0.6);
      if (p.t >= 1) {
        this.scene.remove(p.mesh);
        p.mesh.geometry.dispose();
        this.packets.splice(i, 1);
      }
    }

    for (let i = this.floaters.length - 1; i >= 0; i--) {
      const f = this.floaters[i];
      f.life -= dt;
      f.sprite.position.y += dt * 0.9;
      (f.sprite.material as THREE.SpriteMaterial).opacity = Math.max(0, f.life / 2.2);
      if (f.life <= 0) {
        this.scene.remove(f.sprite);
        this.floaters.splice(i, 1);
      }
    }

    this.stars.rotation.y += dt * 0.01;
    this.controls.update();
    this.composer.render();
  };

  // ---- events ------------------------------------------------------------------

  private packet(fromId: string, toId: string, color: number) {
    const a = this.nodes.get(fromId), b = this.nodes.get(toId);
    if (!a || !b) return;
    const mesh = new THREE.Mesh(new THREE.SphereGeometry(0.22, 12, 12), new THREE.MeshBasicMaterial({ color }));
    this.scene.add(mesh);
    this.packets.push({ mesh, from: a.pos.clone(), to: b.pos.clone(), t: 0, speed: 0.9, bounce: false });
  }
  private float(id: string, text: string, ok = true) {
    const n = this.nodes.get(id);
    if (!n) return;
    const sp = labelSprite(text, ok ? '#e6edf3' : '#ff6b6b', 48);
    sp.position.copy(n.pos).add(new THREE.Vector3((Math.random() - 0.5) * 1.2, 2.2, (Math.random() - 0.5) * 1.2));
    sp.scale.multiplyScalar(0.8);
    this.scene.add(sp);
    this.floaters.push({ sprite: sp, life: 2.2 });
  }
  private feed(text: string, cls = '') {
    const ol = this.element().querySelector('.feed') as HTMLElement;
    const li = Object.assign(document.createElement('li'), { textContent: `${new Date().toLocaleTimeString()}  ${text}`, className: cls });
    ol.prepend(li);
    while (ol.children.length > 40) ol.lastChild?.remove();
  }
  private coordId() {
    return this.data.agents.find((a) => a.role === 'coordinator')?.id ?? 'caelum';
  }

  /** Single path for real (polled) and simulated activity. */
  private ingest(a: Activity) {
    const working = new Set(a.agents.filter((x) => x.working).map((x) => x.id));
    for (const n of this.nodes.values()) {
      n.working = working.has(n.id) || (n.id === this.coordId() && a.running_jobs > 0);
      const li = this.element().querySelector(`.legend li[data-id="${n.id}"] .st`);
      if (li) li.textContent = n.working ? 'trabajando' : '';
    }
    const coord = this.coordId();
    if (this.primed) {
      for (const t of a.tasks as ActivityTask[]) {
        const prev = this.taskState.get(t.id);
        if (prev === t.status) continue;
        const color = COLORS[t.worker_id] ?? 0xffffff;
        if (!prev) {
          this.packet(coord, t.worker_id, color);
          this.feed(`→ ${t.worker_id}: ${t.description ?? 'tarea delegada'}`);
        }
        if (t.status === 'completed' || t.status === 'failed') {
          this.packet(t.worker_id, coord, color);
          this.feed(`${t.status === 'completed' ? '✓' : '✗'} ${t.worker_id} ${t.status}`, t.status === 'failed' ? 'bad' : 'ok');
        }
      }
      for (const tr of [...a.traces].reverse()) {
        if (this.seenTrace.has(tr.id)) continue;
        const n = this.nodes.get(tr.agent_id);
        if (n) n.flash = 1;
        this.float(tr.agent_id, `${tr.tool_name}${tr.success === false ? ' ✗' : ''}`, tr.success !== false);
        this.feed(`${tr.agent_id} · ${tr.tool_name}${tr.duration_ms ? ` (${tr.duration_ms}ms)` : ''}`, tr.success === false ? 'bad' : '');
      }
    }
    a.tasks.forEach((t) => this.taskState.set(t.id, t.status));
    a.traces.forEach((t) => this.seenTrace.add(t.id));
    this.primed = true;
  }

  private async refresh() {
    if (this.simulating) return;
    try {
      this.ingest(await api<Activity>('/activity'));
    } catch {
      /* transient */
    }
  }

  // ---- simulation (same ingest path, clearly labelled) ----------------------------

  @on('click', '.sim')
  private toggleSim() {
    this.simulating = !this.simulating;
    const btn = this.element().querySelector('.sim') as HTMLElement;
    btn.textContent = this.simulating ? '■ Detener simulación' : '▶ Simular actividad';
    (this.element().querySelector('.sim-badge') as HTMLElement).hidden = !this.simulating;
    this.simTimers.forEach(clearTimeout);
    this.simTimers = [];
    if (!this.simulating) {
      this.primed = false;
      this.taskState.clear();
      return;
    }
    const workers = this.data.agents.filter((a) => a.role !== 'coordinator').map((a) => a.id);
    const state: Activity = { now: '', agents: this.data.agents.map((a) => ({ ...a, working: false })), tasks: [], traces: [], running_jobs: 0 };
    this.primed = true;
    let seq = 0;
    const step = () => {
      if (!this.simulating) return;
      const w = workers[Math.floor(Math.random() * workers.length)];
      const id = `sim-${++seq}`;
      state.running_jobs = 1;
      state.tasks.unshift({ id, worker_id: w, status: 'running', description: 'tarea simulada' });
      state.agents.find((x) => x.id === w)!.working = true;
      this.ingest(state);
      for (let i = 1; i <= 3; i++) {
        this.simTimers.push(window.setTimeout(() => {
          state.traces.unshift({ id: `${id}-t${i}`, agent_id: w, tool_name: SIM_TOOLS[Math.floor(Math.random() * SIM_TOOLS.length)], success: Math.random() > 0.1, duration_ms: 200 + Math.floor(Math.random() * 1800), created_at: '' });
          this.ingest(state);
        }, i * 700));
      }
      this.simTimers.push(window.setTimeout(() => {
        state.tasks.find((t) => t.id === id)!.status = 'completed';
        state.agents.find((x) => x.id === w)!.working = false;
        state.running_jobs = 0;
        this.ingest(state);
      }, 3300));
      this.simTimers.push(window.setTimeout(step, 1800 + Math.random() * 1200));
    };
    step();
  }
}

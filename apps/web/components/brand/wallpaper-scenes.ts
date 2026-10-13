/**
 * Scenes for the live wallpaper, drawn with Canvas 2D. Original artwork in
 * the spirit of the reference clips (hyperspace light streaks, a glowing
 * networked globe, a constellation of connected nodes, energy trails), not
 * copies of them, so there is nothing to license or download.
 *
 * Each scene keeps its own state, is told its size, and draws one frame per
 * call. LiveWallpaper owns timing, cross-fades and the aurora underneath.
 */

export type SceneName = 'network' | 'warp' | 'globe' | 'trails';
export const SCENE_ORDER: SceneName[] = ['warp', 'globe', 'network', 'trails'];

export type Palette = {
  /** Soft background glows (rgb triplets). */
  glows: string[];
  /** Main accent, secondary accent, bright core. */
  accent: string;
  accent2: string;
  core: string;
  /** Neutral dots/lines. */
  ink: string;
  light: boolean;
};

export const PALETTES = {
  ember: {
    dark: { glows: ['255, 40, 3', '255, 151, 66', '192, 32, 0', '255, 90, 30'], accent: '255, 120, 40', accent2: '255, 40, 3', core: '255, 236, 220', ink: '240, 240, 238', light: false },
    light: { glows: ['255, 64, 20', '255, 151, 66', '212, 32, 0', '255, 120, 60'], accent: '212, 32, 0', accent2: '184, 86, 0', core: '120, 20, 0', ink: '24, 24, 24', light: true },
  },
  cyber: {
    dark: { glows: ['37, 99, 235', '56, 189, 248', '124, 58, 237', '14, 165, 233'], accent: '56, 189, 248', accent2: '168, 85, 247', core: '224, 242, 254', ink: '191, 219, 254', light: false },
    light: { glows: ['59, 130, 246', '56, 189, 248', '139, 92, 246', '14, 165, 233'], accent: '29, 78, 216', accent2: '124, 58, 237', core: '30, 58, 138', ink: '15, 23, 42', light: true },
  },
} satisfies Record<string, { dark: Palette; light: Palette }>;

export type WallpaperColor = keyof typeof PALETTES;

const hexRgb = (hex: string) => {
  const n = parseInt(hex.slice(1), 16);
  return `${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}`;
};

/** A wallpaper palette built from a colour theme's accents. */
export function paletteFromAccent(main: string, second: string, deep: string, light: boolean): Palette {
  const m = hexRgb(main);
  const s2 = hexRgb(second);
  const d = hexRgb(deep);
  return light
    ? { glows: [m, s2, d, s2], accent: d, accent2: m, core: d, ink: '24, 24, 24', light: true }
    : { glows: [m, s2, d, s2], accent: s2, accent2: m, core: '245, 243, 255', ink: '226, 226, 236', light: false };
}

export type Pointer = { x: number; y: number }; // 0..1, eased by the caller

export interface Scene {
  resize(width: number, height: number): void;
  draw(ctx: CanvasRenderingContext2D, dt: number, now: number, pointer: Pointer): void;
}

function seeded(seed: number) {
  let s = seed;
  return () => {
    s = (s * 16807) % 2147483647;
    return s / 2147483647;
  };
}

function glowDot(ctx: CanvasRenderingContext2D, x: number, y: number, r: number, rgb: string, alpha: number) {
  const g = ctx.createRadialGradient(x, y, 0, x, y, r);
  g.addColorStop(0, `rgba(${rgb}, ${alpha})`);
  g.addColorStop(1, `rgba(${rgb}, 0)`);
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fill();
}

// ── Network: drifting nodes, links, sparks travelling along them ─────────

function networkScene(p: Palette, density: number): Scene {
  type Node = { x: number; y: number; vx: number; vy: number };
  type Pulse = { a: number; b: number; t: number; speed: number };
  let w = 0;
  let h = 0;
  let nodes: Node[] = [];
  let pulses: Pulse[] = [];
  let spawn = 0;
  const LINK = 175;
  return {
    resize(width, height) {
      w = width;
      h = height;
      const rand = seeded(11);
      const count = Math.round(Math.min(110, (w * h) / 14000) * density);
      nodes = Array.from({ length: count }, () => ({
        x: rand() * w,
        y: rand() * h,
        vx: (rand() - 0.5) * 0.012,
        vy: (rand() - 0.5) * 0.012,
      }));
      pulses = [];
    },
    draw(ctx, dt, _now, pointer) {
      const px = (pointer.x - 0.5) * 24;
      const py = (pointer.y - 0.5) * 24;
      for (const n of nodes) {
        n.x += n.vx * dt;
        n.y += n.vy * dt;
        if (n.x < -20) n.x = w + 20;
        if (n.x > w + 20) n.x = -20;
        if (n.y < -20) n.y = h + 20;
        if (n.y > h + 20) n.y = -20;
      }
      const links: Array<[number, number]> = [];
      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i += 1) {
        for (let j = i + 1; j < nodes.length; j += 1) {
          const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
          if (d < LINK) {
            links.push([i, j]);
            ctx.strokeStyle = `rgba(${p.accent}, ${(1 - d / LINK) * (p.light ? 0.4 : 0.5)})`;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x + px, nodes[i].y + py);
            ctx.lineTo(nodes[j].x + px, nodes[j].y + py);
            ctx.stroke();
          }
        }
      }
      ctx.fillStyle = `rgba(${p.ink}, ${p.light ? 0.45 : 0.6})`;
      for (const n of nodes) {
        ctx.beginPath();
        ctx.arc(n.x + px, n.y + py, 1.6, 0, Math.PI * 2);
        ctx.fill();
      }
      spawn += dt;
      if (spawn > 600 && links.length > 0) {
        spawn = 0;
        const [a, b] = links[Math.floor(Math.random() * links.length)];
        pulses.push({ a, b, t: 0, speed: 0.0006 + Math.random() * 0.0006 });
      }
      pulses = pulses.filter((pulse) => {
        pulse.t += pulse.speed * dt;
        const from = nodes[pulse.a];
        const to = nodes[pulse.b];
        if (pulse.t >= 1 || !from || !to) return false;
        glowDot(ctx, from.x + (to.x - from.x) * pulse.t + px, from.y + (to.y - from.y) * pulse.t + py, 9, p.core, 0.9);
        return true;
      });
    },
  };
}

// ── Warp: stars rushing past as light streaks (hyperspace tunnel) ────────

function warpScene(p: Palette, density: number): Scene {
  type Star = { x: number; y: number; z: number; pz: number; tint: number };
  let w = 0;
  let h = 0;
  let stars: Star[] = [];
  const rand = Math.random;
  const reset = (s: Star, far: boolean) => {
    s.x = (rand() - 0.5) * 2.2;
    s.y = (rand() - 0.5) * 2.2;
    s.z = far ? 1 : 0.15 + rand() * 0.85;
    s.pz = s.z;
    s.tint = rand();
  };
  return {
    resize(width, height) {
      w = width;
      h = height;
      const count = Math.round(Math.min(480, (w * h) / 2600) * density);
      stars = Array.from({ length: count }, () => {
        const s = { x: 0, y: 0, z: 1, pz: 1, tint: 0 };
        reset(s, false);
        return s;
      });
    },
    draw(ctx, dt, now, pointer) {
      const cx = w * (0.5 + (pointer.x - 0.5) * 0.08);
      const cy = h * (0.5 + (pointer.y - 0.5) * 0.08);
      const f = Math.min(w, h) * 0.5;
      // Breathing speed: cruise, then a gentle surge every few seconds.
      const speed = 0.00016 + 0.00012 * Math.max(0, Math.sin(now * 0.0004));

      glowDot(ctx, cx, cy, Math.min(w, h) * 0.35, p.accent, p.light ? 0.12 : 0.22);

      ctx.lineCap = 'round';
      for (const s of stars) {
        s.pz = s.z;
        s.z -= speed * dt;
        if (s.z <= 0.02) {
          reset(s, true);
          continue;
        }
        const x = cx + (s.x / s.z) * f;
        const y = cy + (s.y / s.z) * f;
        const ox = cx + (s.x / s.pz) * f;
        const oy = cy + (s.y / s.pz) * f;
        if (x < -50 || x > w + 50 || y < -50 || y > h + 50) {
          reset(s, true);
          continue;
        }
        const near = 1 - s.z;
        const rgb = s.tint < 0.18 ? p.accent2 : s.tint < 0.45 ? p.accent : p.core;
        ctx.strokeStyle = `rgba(${rgb}, ${Math.min(1, near * 1.2) * (p.light ? 0.7 : 0.9)})`;
        ctx.lineWidth = 0.5 + near * 2.2;
        ctx.beginPath();
        // Stretch the streak a little beyond one frame's travel for a long-exposure look.
        ctx.moveTo(ox - (x - ox) * 2, oy - (y - oy) * 2);
        ctx.lineTo(x, y);
        ctx.stroke();
      }
    },
  };
}

// ── Globe: a dotted planet with arcs of data travelling between points ───

function globeScene(p: Palette, density: number): Scene {
  type Vec = [number, number, number];
  type Arc = { a: Vec; b: Vec; t: number; speed: number };
  let w = 0;
  let h = 0;
  let points: Vec[] = [];
  let hubs: Vec[] = [];
  let arcs: Arc[] = [];
  let angle = 0;
  let spawn = 0;
  const tilt = 0.38;

  const project = (v: Vec, cx: number, cy: number, r: number) => {
    // Spin around Y, then tilt toward the viewer around X.
    const cosA = Math.cos(angle);
    const sinA = Math.sin(angle);
    const x1 = v[0] * cosA + v[2] * sinA;
    const z1 = -v[0] * sinA + v[2] * cosA;
    const y2 = v[1] * Math.cos(tilt) - z1 * Math.sin(tilt);
    const z2 = v[1] * Math.sin(tilt) + z1 * Math.cos(tilt);
    return { x: cx + x1 * r, y: cy + y2 * r, z: z2 };
  };

  const slerp = (a: Vec, b: Vec, t: number): Vec => {
    const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const omega = Math.acos(dot);
    if (omega < 1e-4) return a;
    const s = Math.sin(omega);
    const k1 = Math.sin((1 - t) * omega) / s;
    const k2 = Math.sin(t * omega) / s;
    return [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2];
  };

  return {
    resize(width, height) {
      w = width;
      h = height;
      const n = Math.round(Math.min(1400, (w * h) / 900) * density);
      points = [];
      const golden = Math.PI * (3 - Math.sqrt(5));
      for (let i = 0; i < n; i += 1) {
        const y = 1 - (i / (n - 1)) * 2;
        const radius = Math.sqrt(1 - y * y);
        const theta = golden * i;
        points.push([Math.cos(theta) * radius, y, Math.sin(theta) * radius]);
      }
      const rand = seeded(29);
      hubs = Array.from({ length: 18 }, () => points[Math.floor(rand() * points.length)]);
      arcs = [];
    },
    draw(ctx, dt, _now, pointer) {
      const wide = w > 900;
      const r = Math.min(w, h) * (wide ? 0.4 : 0.36);
      const cx = w * (wide ? 0.66 : 0.5) + (pointer.x - 0.5) * 20;
      const cy = h * (wide ? 0.52 : 0.58) + (pointer.y - 0.5) * 20;
      angle += dt * 0.00009;

      // Atmosphere
      glowDot(ctx, cx, cy, r * 1.35, p.accent, p.light ? 0.12 : 0.2);
      ctx.strokeStyle = `rgba(${p.accent}, ${p.light ? 0.25 : 0.35})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      // Surface dots: bright on the near side, faint on the far side.
      for (const v of points) {
        const q = project(v, cx, cy, r);
        const a = q.z > 0 ? 0.35 + q.z * 0.65 : 0.08;
        ctx.fillStyle = `rgba(${q.z > 0.55 ? p.core : p.ink}, ${a * (p.light ? 0.7 : 1)})`;
        const size = q.z > 0 ? 1.6 + q.z * 1.2 : 1.2;
        ctx.fillRect(q.x - size / 2, q.y - size / 2, size, size);
      }

      // Hubs
      for (const hub of hubs) {
        const q = project(hub, cx, cy, r);
        if (q.z > 0) glowDot(ctx, q.x, q.y, 7, p.accent2, 0.8 * q.z);
      }

      // Arcs between hubs, lifted off the surface, drawn as they travel.
      spawn += dt;
      if (spawn > 900 && arcs.length < 7) {
        spawn = 0;
        const a = hubs[Math.floor(Math.random() * hubs.length)];
        const b = hubs[Math.floor(Math.random() * hubs.length)];
        if (a !== b) arcs.push({ a, b, t: 0, speed: 0.00035 + Math.random() * 0.0003 });
      }
      arcs = arcs.filter((arc) => {
        arc.t += arc.speed * dt;
        if (arc.t > 1.6) return false;
        const head = Math.min(1, arc.t);
        const tail = Math.max(0, arc.t - 0.6);
        const steps = 28;
        ctx.lineWidth = 1.4;
        let prev: { x: number; y: number; z: number } | null = null;
        for (let i = 0; i <= steps; i += 1) {
          const t = tail + ((head - tail) * i) / steps;
          const v = slerp(arc.a, arc.b, t);
          const lift = 1 + Math.sin(Math.PI * t) * 0.22;
          const q = project([v[0] * lift, v[1] * lift, v[2] * lift], cx, cy, r);
          if (prev && (q.z > -0.15 || prev.z > -0.15)) {
            ctx.strokeStyle = `rgba(${p.accent}, ${(i / steps) * (p.light ? 0.75 : 0.9)})`;
            ctx.beginPath();
            ctx.moveTo(prev.x, prev.y);
            ctx.lineTo(q.x, q.y);
            ctx.stroke();
          }
          prev = q;
        }
        if (prev && arc.t < 1 && prev.z > -0.15) glowDot(ctx, prev.x, prev.y, 8, p.core, 0.95);
        return true;
      });
    },
  };
}

// ── Trails: glowing energy streaks sweeping across ───────────────────────

function trailsScene(p: Palette, density: number): Scene {
  type Comet = { x: number; y: number; vx: number; vy: number; phase: number; wobble: number; hue: string; tail: Array<[number, number]>; width: number };
  let w = 0;
  let h = 0;
  let comets: Comet[] = [];
  let sparks: Array<{ x: number; y: number; vx: number; vy: number; life: number; hue: string }> = [];

  const spawn = (): Comet => {
    const fromLeft = Math.random() < 0.5;
    const speed = 0.12 + Math.random() * 0.12;
    const dir = (Math.random() - 0.5) * 0.6 + (fromLeft ? 0 : Math.PI);
    return {
      x: fromLeft ? -40 : w + 40,
      y: h * (0.15 + Math.random() * 0.7),
      vx: Math.cos(dir) * speed,
      vy: Math.sin(dir) * speed,
      phase: Math.random() * Math.PI * 2,
      wobble: 0.5 + Math.random(),
      hue: Math.random() < 0.5 ? p.accent : p.accent2,
      tail: [],
      width: 2 + Math.random() * 2.5,
    };
  };

  return {
    resize(width, height) {
      w = width;
      h = height;
      const count = Math.max(4, Math.round(8 * density));
      comets = Array.from({ length: count }, () => {
        const c = spawn();
        c.x = Math.random() * w;
        return c;
      });
      sparks = [];
    },
    draw(ctx, dt, now) {
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      comets = comets.map((c) => {
        const bend = Math.sin(now * 0.0012 * c.wobble + c.phase) * 0.05;
        c.x += (c.vx - c.vy * bend) * dt;
        c.y += (c.vy + c.vx * bend) * dt;
        c.tail.unshift([c.x, c.y]);
        if (c.tail.length > 48) c.tail.pop();
        if (Math.random() < 0.25) {
          sparks.push({ x: c.x, y: c.y, vx: (Math.random() - 0.5) * 0.08, vy: (Math.random() - 0.5) * 0.08, life: 1, hue: c.hue });
        }
        // Tail: thick and bright at the head, fading to nothing.
        for (let i = 1; i < c.tail.length; i += 1) {
          const k = 1 - i / c.tail.length;
          ctx.strokeStyle = `rgba(${i < 6 ? p.core : c.hue}, ${k * (p.light ? 0.6 : 0.85)})`;
          ctx.lineWidth = c.width * k + 0.3;
          ctx.beginPath();
          ctx.moveTo(c.tail[i - 1][0], c.tail[i - 1][1]);
          ctx.lineTo(c.tail[i][0], c.tail[i][1]);
          ctx.stroke();
        }
        glowDot(ctx, c.x, c.y, 26, c.hue, p.light ? 0.4 : 0.7);
        glowDot(ctx, c.x, c.y, 6, p.core, 1);
        const gone = c.x < -120 || c.x > w + 120 || c.y < -120 || c.y > h + 120;
        return gone ? spawn() : c;
      });
      sparks = sparks.filter((s) => {
        s.life -= dt * 0.0012;
        if (s.life <= 0) return false;
        s.x += s.vx * dt;
        s.y += s.vy * dt;
        ctx.fillStyle = `rgba(${s.hue}, ${s.life * 0.8})`;
        ctx.fillRect(s.x - 1, s.y - 1, 2, 2);
        return true;
      });
    },
  };
}

export function createScene(name: SceneName, palette: Palette, density: number): Scene {
  switch (name) {
    case 'warp':
      return warpScene(palette, density);
    case 'globe':
      return globeScene(palette, density);
    case 'trails':
      return trailsScene(palette, density);
    default:
      return networkScene(palette, density);
  }
}

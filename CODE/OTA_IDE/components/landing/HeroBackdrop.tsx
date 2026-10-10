'use client';

import React from 'react';
import { useReducedMotion } from './motion';

/**
 * Hero background, three layers:
 *
 * 1. An optional looping video (public/brand/hero-loop.mp4/.webm, see
 *    docs/design/HERO_VIDEO_PROMPT.md). Only rendered when the server found
 *    the file, faded in once it can play, never shown with reduced motion.
 * 2. A canvas "fleet": devices scattered around a gateway, signed packages
 *    travelling out, heartbeats travelling back, and the occasional package
 *    rejected before it reaches a board. It is the product, drawn.
 * 3. A soft amber spotlight that follows the pointer.
 *
 * The canvas pauses when the hero is off-screen or the tab is hidden, and
 * draws a single still frame under reduced motion.
 */

type Node = { x: number; y: number; r: number; glow: number; phase: number };
type Packet = { from: Node; to: Node; t: number; speed: number; kind: 'update' | 'heartbeat' | 'rejected' };

const EMBER = '255, 40, 3';
const AMBER = '255, 151, 66';
const BONE = '240, 240, 238';

export function HeroBackdrop({ videoSources }: { videoSources: Array<{ src: string; type: string }> }) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const wrapRef = React.useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();
  const [videoReady, setVideoReady] = React.useState(false);
  const videoRef = React.useRef<HTMLVideoElement>(null);

  // The video is in the server HTML, so it can become playable before React
  // attaches onCanPlay. Check its state once mounted as well.
  React.useEffect(() => {
    const video = videoRef.current;
    if (video && video.readyState >= 3) setVideoReady(true);
  }, [videoSources.length, reduced]);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let gateway: Node = { x: 0, y: 0, r: 7, glow: 0, phase: 0 };
    let devices: Node[] = [];
    let packets: Packet[] = [];
    let frame = 0;
    let visible = true;
    let last = performance.now();
    let spawn = 0;

    const layout = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = wrap.clientWidth;
      height = wrap.clientHeight;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // The fleet sits on the right so the headline stays on a calm field.
      const narrow = width < 760;
      gateway = { x: width * (narrow ? 0.5 : 0.72), y: height * (narrow ? 0.88 : 0.46), r: 7, glow: 0, phase: 0 };
      const count = narrow ? 12 : 22;
      devices = [];
      let seed = 7;
      const rand = () => {
        seed = (seed * 16807) % 2147483647;
        return seed / 2147483647;
      };
      for (let i = 0; i < count; i += 1) {
        const angle = (i / count) * Math.PI * 2 + rand() * 0.4;
        const ring = 0.45 + rand() * 0.55;
        const rx = (narrow ? width * 0.46 : width * 0.3) * ring;
        const ry = (narrow ? height * 0.2 : height * 0.36) * ring;
        devices.push({
          x: gateway.x + Math.cos(angle) * rx,
          y: gateway.y + Math.sin(angle) * ry,
          r: 2.6 + rand() * 1.6,
          glow: 0,
          phase: rand() * Math.PI * 2,
        });
      }
      packets = [];
    };

    const draw = (now: number, animate: boolean) => {
      const dt = Math.min(64, now - last);
      last = now;
      ctx.clearRect(0, 0, width, height);

      // Links
      for (const device of devices) {
        const gradient = ctx.createLinearGradient(gateway.x, gateway.y, device.x, device.y);
        gradient.addColorStop(0, `rgba(${EMBER}, 0.22)`);
        gradient.addColorStop(1, `rgba(${BONE}, 0.04)`);
        ctx.strokeStyle = gradient;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(gateway.x, gateway.y);
        ctx.lineTo(device.x, device.y);
        ctx.stroke();
      }

      if (animate) {
        spawn += dt;
        if (spawn > 260) {
          spawn = 0;
          const device = devices[Math.floor(Math.random() * devices.length)];
          const roll = Math.random();
          packets.push(
            roll < 0.55
              ? { from: device, to: gateway, t: 0, speed: 0.0007 + Math.random() * 0.0004, kind: 'heartbeat' }
              : roll < 0.9
                ? { from: gateway, to: device, t: 0, speed: 0.00045 + Math.random() * 0.0003, kind: 'update' }
                : { from: gateway, to: device, t: 0, speed: 0.0005, kind: 'rejected' }
          );
        }
      }

      // Packets
      packets = packets.filter((packet) => {
        if (animate) packet.t += packet.speed * dt;
        const limit = packet.kind === 'rejected' ? 0.62 : 1;
        if (packet.t >= limit) {
          if (packet.kind === 'update') packet.to.glow = 1;
          if (packet.kind === 'heartbeat') gateway.glow = Math.min(1, gateway.glow + 0.25);
          if (packet.kind === 'rejected') {
            // Burst where the verifier stopped it.
            const x = packet.from.x + (packet.to.x - packet.from.x) * limit;
            const y = packet.from.y + (packet.to.y - packet.from.y) * limit;
            ctx.strokeStyle = `rgba(${EMBER}, 0.9)`;
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(x - 5, y - 5);
            ctx.lineTo(x + 5, y + 5);
            ctx.moveTo(x + 5, y - 5);
            ctx.lineTo(x - 5, y + 5);
            ctx.stroke();
          }
          return false;
        }
        const x = packet.from.x + (packet.to.x - packet.from.x) * packet.t;
        const y = packet.from.y + (packet.to.y - packet.from.y) * packet.t;
        const color = packet.kind === 'heartbeat' ? BONE : packet.kind === 'rejected' ? EMBER : AMBER;
        const size = packet.kind === 'heartbeat' ? 1.6 : 2.4;
        const halo = ctx.createRadialGradient(x, y, 0, x, y, size * 6);
        halo.addColorStop(0, `rgba(${color}, ${packet.kind === 'heartbeat' ? 0.5 : 0.9})`);
        halo.addColorStop(1, `rgba(${color}, 0)`);
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(x, y, size * 6, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = `rgba(${color}, 1)`;
        ctx.beginPath();
        ctx.arc(x, y, size, 0, Math.PI * 2);
        ctx.fill();
        return true;
      });

      // Devices
      for (const device of devices) {
        device.phase += dt * 0.002;
        device.glow = Math.max(0, device.glow - dt * 0.0012);
        const breathe = 0.35 + Math.sin(device.phase) * 0.15;
        if (device.glow > 0) {
          ctx.fillStyle = `rgba(${AMBER}, ${device.glow * 0.35})`;
          ctx.beginPath();
          ctx.arc(device.x, device.y, device.r + 12 * device.glow, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.fillStyle = `rgba(${BONE}, ${breathe + device.glow * 0.5})`;
        ctx.beginPath();
        ctx.arc(device.x, device.y, device.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // Gateway
      gateway.glow = Math.max(0, gateway.glow - dt * 0.0015);
      const g = ctx.createRadialGradient(gateway.x, gateway.y, 0, gateway.x, gateway.y, 46);
      g.addColorStop(0, `rgba(${EMBER}, ${0.55 + gateway.glow * 0.35})`);
      g.addColorStop(1, `rgba(${EMBER}, 0)`);
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(gateway.x, gateway.y, 46, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#fff';
      ctx.beginPath();
      ctx.arc(gateway.x, gateway.y, gateway.r, 0, Math.PI * 2);
      ctx.fill();
    };

    const loop = (now: number) => {
      draw(now, true);
      if (visible && !document.hidden) frame = requestAnimationFrame(loop);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      last = performance.now();
      if (reduced) {
        draw(last, false);
      } else if (visible && !document.hidden) {
        frame = requestAnimationFrame(loop);
      }
    };

    layout();
    start();

    const resize = new ResizeObserver(() => {
      layout();
      start();
    });
    resize.observe(wrap);

    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      start();
    });
    io.observe(wrap);

    const onVisibility = () => start();
    document.addEventListener('visibilitychange', onVisibility);

    // The copy sits above this layer, so listen on the hero section itself.
    const host = wrap.parentElement;
    const onPointerMove = (event: PointerEvent) => {
      const rect = wrap.getBoundingClientRect();
      wrap.style.setProperty('--mx', `${event.clientX - rect.left}px`);
      wrap.style.setProperty('--my', `${event.clientY - rect.top}px`);
    };
    host?.addEventListener('pointermove', onPointerMove);

    return () => {
      host?.removeEventListener('pointermove', onPointerMove);
      cancelAnimationFrame(frame);
      resize.disconnect();
      io.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [reduced]);

  return (
    <div ref={wrapRef} className="lp-hero-media" aria-hidden="true">
      {videoSources.length > 0 && !reduced && (
        <video
          ref={videoRef}
          autoPlay
          muted
          loop
          playsInline
          preload="metadata"
          poster="/brand/landing-bg.jpg"
          data-ready={videoReady ? 'true' : 'false'}
          onCanPlay={() => setVideoReady(true)}
          onLoadedData={() => setVideoReady(true)}
        >
          {videoSources.map((source) => (
            <source key={source.src} src={source.src} type={source.type} />
          ))}
        </video>
      )}
      <div className="lp-hero-shade" />
      <canvas ref={canvasRef} />
      <div className="lp-hero-spot" />
    </div>
  );
}

# SecureOTA — Claude Design Prompt

Copy everything inside the prompt block below into Claude (or Claude Design) and
**attach your reference images in the same message**. The prompt tells the model to treat
those images as the visual north star and to build to Vercel's Web Interface Guidelines.

---

## PROMPT — copy from here ↓

You are a senior product designer and front-end engineer. Design and build the front end
for **SecureOTA**, a secure over-the-air firmware update platform for IoT/ESP32 device
fleets. Produce a **professional, modern, high-performance** web interface. Match the look
and feel of the reference images I have attached, and follow the engineering rules below
exactly.

### Reference images (visual north star)
I have attached reference images. Treat them as the source of truth for the aesthetic.
Before designing, extract and then commit to:
- the **color palette** (background, surface, primary/accent, semantic success/warning/
  error, borders) and whether it is light-first, dark-first, or both;
- the **typography** (font family or nearest system/Google-Fonts equivalent, weights,
  heading scale, use of mono for technical values);
- the **layout density and shape language** (corner radii, border weight, shadow depth,
  spacing rhythm, card vs. flat surfaces);
- the **motion feel** (subtle/instant vs. expressive).
If any image conflicts with a rule below, keep the rule's *behavior* (accessibility,
performance, semantics) and adapt the *look* to the image.

### Product context and business needs
SecureOTA lets an operator manage a device fleet, publish cryptographically signed
firmware, and deliver it two ways: **Serial (USB)** flashing of an attached board, and
**OTA (network)** delivery that devices poll and self-apply. Business goals: look
trustworthy enough for a security product, be fast and responsive under real fleet data,
and make the risky actions (touching hardware, pushing firmware) feel deliberate and
auditable. The device is always the source of truth — the UI reflects device heartbeats
and never claims success optimistically.

### Primary user and the core flow to design (login → code upload)
Design the whole journey and every screen it touches:
1. **Login** — split-screen: brand/value panel + credential form.
2. **Dashboard** — glanceable fleet health, latest signed release, pipeline status.
3. **Devices → Host Access** — a consent gate: detected COM ports and local networks are
   locked until the operator grants access (grants expire); includes local-network device
   discovery.
4. **Devices → Connection** — tabbed Serial vs. OTA; select port/board/WiFi/sketch and
   flash, or check + push an OTA target; live progress + serial monitor.
5. **Releases → Publish firmware** — upload a signed `.bin`, set version + compatible
   architectures; list of releases.
6. **Pipeline** — measured build stages (artifact → store → sign → **verify**), the verify
   stage styled as the trust anchor.
7. **Manifest** — read-only signed-manifest inspector (version, SHA-256, signature,
   download URL, compatible list).
8. Supporting: Event Logs, ASH device-health monitor, Key Vault, Settings + a grants/
   Access audit view.
Show how screens connect (navigation + the flow from granting access to a confirmed
update).

### Layout & shell
One authenticated shell: collapsible left **Sidebar** (grouped nav: Monitor / Deploy /
Security / Config, live online/offline counts), a **TopBar** (breadcrumb + user menu with
sign-out), page content area, and a **StatusBar** (gateway reachability + UTC clock). On
mobile the sidebar becomes a slide-over sheet.

### Visual system rules (Vercel Web Interface Guidelines)
- **Depth:** layered shadows (at least two layers, ambient + direct light). Combine
  borders with shadows; use semi-transparent borders for crisp edges.
- **Radii:** nested/concentric — a child's corner radius never exceeds its parent's.
- **Color:** on colored surfaces, tint borders/shadows/text toward the same hue. Judge
  contrast with **APCA**, not just WCAG 2. Interactive states (hover/active/focus) must
  have **more** contrast than the resting state. Never rely on color alone — pair every
  status with a text label and/or icon. Set `<meta name="theme-color">` to the page bg.
- **Type:** curly quotes (" ") not straight; real ellipsis (…); `font-variant-numeric:
  tabular-nums` for any aligned numbers (versions, byte counts, latencies); non-breaking
  spaces between a value and its unit ("10 MB", "115200 baud"); tidy line-rag, no widows.
- **Alignment:** every element aligns to a grid, baseline, edge, or center on purpose;
  optical ±1px adjustments where perception beats geometry.

### Motion
- Only animate to clarify cause/effect or for intentional delight. Provide a
  `prefers-reduced-motion` variant.
- Prefer CSS over the Web Animations API over JS libraries. Animate only
  GPU-friendly properties (`transform`, `opacity`); avoid layout-triggering ones.
- Never `transition: all` — list the exact properties. Animations must be interruptible
  by user input, and anchored to a correct transform-origin.

### Performance (this must feel fast)
- Network budgets: POST/PATCH/DELETE complete in **< 500 ms**; show a spinner only once a
  request is in flight.
- **Virtualize** long lists (event logs, device tables, serial monitor) or use
  `content-visibility: auto`.
- Images: explicit width/height to prevent layout shift; preload only above-the-fold.
- Fonts: subset via `unicode-range`, ship only used scripts.
- Keep the main thread free; minimize re-renders; prefer flex/grid/intrinsic sizing over
  measuring in JS. Only render useful scrollbars; never let the page scroll horizontally —
  wide content scrolls inside its own container.

### Accessibility (non-negotiable)
- Every flow is fully keyboard-operable and follows WAI-ARIA authoring patterns.
- Native semantics first (`button`, `a`, `label`, `table`) before `aria-*`. Visible
  `:focus-visible` rings. Hit targets ≥ 24px (≥ 44px on mobile), with checkbox/radio
  labels sharing the target. Icon-only buttons carry a descriptive `aria-label`. Proper
  `h1–h6` hierarchy plus a "Skip to content" link. Live regions (`role="status"
  aria-live="polite"`) for connection/flash status.

### Forms & inputs
- Keep submit enabled until the request starts, then disable + spinner. Don't block typing
  on validation — show inline feedback instead. Show errors next to their field and focus
  the first error on submit. Set `autocomplete`/`name` for autofill. When a text input is
  the only control, Enter submits; in a textarea, Enter is a newline and Cmd/Ctrl+Enter
  submits.

### Tone & microcopy
- Active, imperative voice ("Grant Access", "Publish Firmware", "Save API Key" — specific,
  not "Submit"). Title Case for buttons and headings. Second person ("you"). Positive
  framing. **Errors guide the exit**: state the cause and the exact next step (e.g.,
  "Access to COM3 hasn't been granted — grant it under Host Access, then retry the flash").

### Tech constraints
Target Next.js 16 (App Router) + React 19 + Tailwind + shadcn/ui + lucide-react. Reuse
semantic design tokens (a `--primary`/`--accent`, a four-hue semantic set for
success/info/warning/error, `--muted`, `--border`, `--card`, `--sidebar-*`) rather than
hard-coded hex. Theme-aware for light and dark.

### Deliverables
1. A short **design-direction statement** naming the aesthetic you committed to and how it
   ties to the reference images.
2. **Design tokens** (color, type scale, spacing, radii, shadow, motion) as CSS variables.
3. **High-fidelity screens** for the flow above, responsive (mobile / laptop / ultra-wide),
   in both light and dark.
4. A **component inventory** (buttons, inputs, cards, tables, badges/status pills, tabs,
   progress, toasts, dialogs, nav) with states (default/hover/focus/active/disabled/
   loading/error).
5. Notes on how the screens **connect** (the login → grant → flash/publish → confirmed
   journey).
Keep it self-contained, accessible, and fast by construction.

## PROMPT — copy to here ↑

---

## Notes for you (not part of the prompt)

- Paste the block above **and attach your reference images in the same message** — the
  prompt is written to read them as the visual source of truth.
- It is grounded in your real app: the flow, screens, shell, and tokens all mirror
  `FRONTEND_DESIGN_PLAN.md`, so what the model designs will map onto the existing
  `app/(dashboard)/` structure.
- The engineering rules are Vercel's Web Interface Guidelines (APCA contrast, layered
  shadows, tabular-nums, reduced-motion, <500 ms network budgets, list virtualization,
  focus-visible, actionable errors) — that is what makes the result read as professional
  and perform fast.

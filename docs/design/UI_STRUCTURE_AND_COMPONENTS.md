# SecureOTA — UI Structure & Component Spec

The structural blueprint to apply your Claude Design system to. This file says **what to
build** (routes, layouts, components, states, data) and stays visual-system-agnostic —
your design system supplies the tokens, type, and styling; this supplies the skeleton.

- **Stack:** Next.js (App Router) · React · Tailwind · shadcn/ui · lucide-react
- **App root:** `CODE/OTA_IDE/`
- **Companion files:** `FRONTEND_DESIGN_PLAN.md` (flows + wireframes), product brief prompt.

---

## 1. What the web app is

A control console for **secure over-the-air firmware updates** to fleets of IoT/ESP32
devices. An operator signs in, sees fleet health, grants the app access to hardware
(COM ports) and the local network, then delivers firmware two ways: **Serial (USB)** flash
of an attached board, or **OTA (network)** — publish a signed binary that devices poll and
self-apply. The device is the source of truth; the UI reflects heartbeats and never claims
success optimistically.

---

## 2. Route map (pages to design)

| Route | Page | Primary job |
|---|---|---|
| `/login` | Login | Authenticate into the console |
| `/dashboard` | Dashboard | Glanceable fleet + release + pipeline health |
| `/devices` | Devices | Inventory + **Host Access** consent + flash/OTA |
| `/event-logs` | Event Logs | Gateway event stream |
| `/pipeline` | Pipeline | Measured build stages (artifact→store→sign→verify) |
| `/releases` | Releases | Release list + publish signed firmware |
| `/manifest` | Manifest | Signed-manifest inspector |
| `/code` | Code | Editor + terminal (compile/flash entry) |
| `/tcv-engine` | TCV Engine | Trust / compatibility / version checks |
| `/ash-monitor` | ASH Monitor | Device health score + quarantine |
| `/key-vault` | Key Vault | Signing keys |
| `/settings` … | Settings, Diagnostics, Reports, Dead Letter, Access, Help, About, Version | Config + audit |

Navigation is grouped: **Monitor** (Dashboard, Devices, Event Logs) · **Deploy**
(Pipeline, Releases, Manifest, Code) · **Security** (TCV, ASH, Key Vault) · **Config**
(the rest).

---

## 3. Layout structure (the shell)

Every authenticated page renders inside one shell:

```
Shell
├─ Sidebar        collapsible (wide ↔ icon-rail); mobile → slide-over sheet
│   ├─ Brand/logo
│   ├─ Nav groups (Monitor / Deploy / Security / Config)
│   └─ Live footer (online / offline counts)
├─ TopBar         mobile menu trigger · breadcrumb/title · user menu (sign out)
├─ Main           page content, padded, max readable width, vertical rhythm
└─ StatusBar      gateway reachability · version · UTC clock
```

Login is the only page **outside** the shell (its own split-screen layout).

---

## 4. Component inventory

### 4.1 Primitives (shadcn/ui — already present, restyle with your system)
`button` · `input` · `select` · `textarea` · `label` · `card` · `badge` · `tabs` ·
`table` · `progress` · `dialog` · `alert-dialog` · `dropdown-menu` · `sheet` ·
`scroll-area` · `skeleton` · `switch` · `tooltip` · `separator` · `popover` ·
`sonner`/`toaster` (toasts).

### 4.2 Layout components
| Component | Role | Key states |
|---|---|---|
| `Sidebar` | primary nav | expanded · collapsed(icon) · mobile-sheet · active-item |
| `TopBar` | context + user menu | default · menu-open |
| `StatusBar` | live system status | reachable · unreachable |
| `PageHeader` | title + primary action per page | with/without action |

### 4.3 Domain components (the app-specific ones)
| Component | Role | Key props / data | States |
|---|---|---|---|
| `MetricCard` | one KPI tile | label, value, tone, delta | loading · value · empty |
| `HostAccessCard` | grant/revoke COM + network, discovery | detected ports, networks, grants | detecting · granted · locked · scanning · results |
| `DeviceConnectionCard` | serial + OTA flashing | ports, board, wifi, firmware, ota host | idle · queued · compiling · uploading · success · failed |
| `PublishFirmwareCard` | upload signed `.bin` | file, version, compatible[] | idle · uploading · verify-fail · success |
| `DeviceTable` | fleet inventory | devices[] | loading(skeleton) · rows · empty · row-actions |
| `EventLog` | streamed events | events[], severity filter | live · paused · empty (virtualized) |
| `PipelineStages` | build stages | stages[] (bytes, hash, ms) | pending · running · success · **verify-abort** |
| `ManifestInspector` | read-only manifest | version, sha256, sig, urls, compatible[] | present · 404-empty |
| `HealthGauge` (ASH) | device health score | score 0–100 | healthy · degraded · **quarantined (<40)** |
| `KeyList` (Key Vault) | signing keys | key ids, algorithm, created | list · empty |
| `CodeEditor` + `Terminal` | edit + compile/flash | files[], selected, output | view · edit(unsaved) · running |
| `PermissionPrompt` 🔴 | reusable 403 → grant CTA | resourceType, resourceId | shown → grant → retry |
| `GrantsTable` 🔴 | audit of active grants | grants[] | list · empty · revoke |
| `StatusPill` | shared status token | tone, label | success/info/warning/error/neutral |

🔴 = to build. Everything else exists and is restyled by your design system.

---

## 5. Data model (entities the UI renders)

| Entity | Key fields | Where shown |
|---|---|---|
| **Device** | id, name, type/arch, status, firmwareVersion, latestVersion, health, lastSync, uptime | Dashboard, Devices, ASH |
| **Release** | version, compatible[], signed, createdAt, sha256, downloadUrl | Releases, Manifest, Dashboard |
| **Deployment** | deviceId, targetVersion, state(pending/confirmed/failed), deadline | Devices, Event Logs |
| **AccessGrant** | resourceType(serial/network), resourceId, grantedBy, expiresAt | Host Access, Access audit |
| **Event** | id, title, description, severity, deviceId, ts | Event Logs, Dashboard |
| **Manifest** | version, sha256, signature, url/downloadUrl, compatible[] | Manifest |
| **PipelineStage** | name, bytes, checksum, keyId, durationMs, status | Pipeline |
| **HostCapability** | detected COM ports, local networks, discovered hosts | Host Access |

All fleet/release/pipeline data arrives via one merged runtime snapshot; grants/host data
via the host-access endpoints.

---

## 6. Page composition (which components each page uses)

- **Login** — split layout: brand panel + credential form (Input, Button, error banner).
- **Dashboard** — `MetricCard`×4, release summary card, `EventLog` (mini), `PipelineStages` (compact).
- **Devices** — `HostAccessCard` → `DeviceConnectionCard` → search `Input` → `DeviceTable` → `MetricCard`×4.
- **Releases** — `PublishFirmwareCard` + releases `Table` with per-arch `StatusPill`.
- **Pipeline** — `PipelineStages` (full), verify stage emphasized as the trust anchor.
- **Manifest** — `ManifestInspector` (copyable hashes).
- **Event Logs** — `EventLog` (virtualized) + severity filter + follow toggle.
- **ASH Monitor** — `HealthGauge` per device + quarantine banner.
- **Key Vault** — `KeyList` (label Ed25519 manifest vs RSA-2048 package distinctly).
- **Code** — `CodeEditor` + file tree + `Terminal`; add Compile / Flash / Publish actions.
- **Settings/Access** — profile, theme, gateway status + `GrantsTable`.

---

## 7. Cross-cutting UI patterns (apply consistently)

| Pattern | Rule |
|---|---|
| Loading | skeletons matching final layout, not bare spinners |
| Empty | icon + one line of what's missing + the fixing action |
| Error | cause + next step; never a raw stack trace |
| Permission denied (403) | name the resource + a one-click grant CTA (`PermissionPrompt`) |
| Toasts | transient success / retryable failure |
| Destructive confirm | inline confirm or `alert-dialog`; revoke/remove/delete |
| Live data | poll snapshot; show "last updated" + reachability |
| Status color | always paired with a text label + icon (never color alone) |

---

## 8. Responsive & accessibility skeleton

- Sidebar → sheet under `md`; grids `1 → md:2 → xl:4`; wide content (tables, logs, code)
  scrolls inside its own container; page never scrolls horizontally.
- Every input has a `<label>`; icon-only buttons carry `aria-label`; visible focus rings;
  status regions `role="status" aria-live="polite"`; heading hierarchy + skip link;
  hit targets ≥ 24px (≥ 44px mobile).

---

## 9. How to apply your Claude Design system

1. Map your system's tokens onto the app's semantic slots: `--primary`/`--accent`,
   a four-tone semantic set (**success / info / warning / error**), `--muted`, `--border`,
   `--card`, `--sidebar-*`. Keep them theme-aware (light + dark).
2. Restyle primitives first (button, input, card, badge, table, tabs) — every page
   inherits them.
3. Then the layout components (Sidebar, TopBar, StatusBar), then domain cards.
4. Keep the **structure, states, and data** in this file intact; change only the look.

_Update the 🔴 rows as they're built; mirror material changes into `PROJECT_LOG.md`._

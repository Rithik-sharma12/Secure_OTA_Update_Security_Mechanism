# OTA IDE

OTA IDE is a Next.js 16 application for the Secure Heterogeneous OTA update control center. The current codebase provides the dashboard shell, route structure, shared UI components, and supporting utilities for firmware management workflows.

## Requirements

- Node.js 20 or newer
- pnpm

## How to Run

From the `CODE/OTA_IDE` folder:

```bash
pnpm install
pnpm dev
```

Open `http://localhost:3000` in your browser. The root route redirects to `/dashboard`.

## Available Scripts

| Command | Purpose |
| --- | --- |
| `pnpm dev` | Start the development server |
| `pnpm build` | Build the production bundle |
| `pnpm start` | Run the production build |
| `pnpm lint` | Run ESLint across the project |

## VS Code Task

The workspace also includes a VS Code task in `.vscode/tasks.json`:

- `Run OTA IDE dev server` -> runs `pnpm dev`

## Application Routes

The app uses the Next.js App Router. The `(dashboard)` folder is a route group, so it does not appear in the URL.

| URL path | Source file |
| --- | --- |
| `/` | `app/page.tsx` |
| `/dashboard` | `app/(dashboard)/dashboard/page.tsx` |
| `/devices` | `app/(dashboard)/devices/page.tsx` |
| `/event-logs` | `app/(dashboard)/event-logs/page.tsx` |
| `/pipeline` | `app/(dashboard)/pipeline/page.tsx` |
| `/releases` | `app/(dashboard)/releases/page.tsx` |
| `/manifest` | `app/(dashboard)/manifest/page.tsx` |
| `/code` | `app/(dashboard)/code/page.tsx` |
| `/tcv-engine` | `app/(dashboard)/tcv-engine/page.tsx` |
| `/ash-monitor` | `app/(dashboard)/ash-monitor/page.tsx` |
| `/key-vault` | `app/(dashboard)/key-vault/page.tsx` |
| `/settings` | `app/(dashboard)/settings/page.tsx` |
| `/diagnostics` | `app/(dashboard)/diagnostics/page.tsx` |
| `/reports` | `app/(dashboard)/reports/page.tsx` |
| `/simulator` | `app/(dashboard)/simulator/page.tsx` |
| `/help` | `app/(dashboard)/help/page.tsx` |
| `/version` | `app/(dashboard)/version/page.tsx` |
| `/terminal` | `app/(dashboard)/terminal/page.tsx` |

## Project Path Index

### App Layer

- `app/layout.tsx` - root layout, metadata, fonts, analytics hook
- `app/globals.css` - global application styles
- `app/page.tsx` - redirects to `/dashboard`
- `app/(dashboard)/layout.tsx` - dashboard shell with sidebar, top bar, status bar, and error boundary
- `app/(dashboard)/*/page.tsx` - route pages for each dashboard feature area

### Components

- `components/theme-provider.tsx` - theme provider wrapper
- `components/dashboard/MetricCard.tsx` - dashboard metric card component
- `components/dashboard/PageHeader.tsx` - shared page header component
- `components/editor/CodeEditor.tsx` - code editor wrapper
- `components/error/ErrorBoundary.tsx` - React error boundary
- `components/error/ErrorFallback.tsx` - fallback UI for render errors
- `components/layout/Sidebar.tsx` - primary navigation and route groups
- `components/layout/TopBar.tsx` - top application bar
- `components/layout/StatusBar.tsx` - bottom status strip
- `components/terminal/Terminal.tsx` - terminal panel component
- `components/ui/*` - reusable UI primitives used across the app

### Hooks

- `hooks/use-mobile.ts` - responsive mobile helper
- `hooks/use-toast.ts` - toast state helper
- `hooks/useErrorHandler.ts` - shared error-handling hook

### Shared Library

- `lib/api-response.ts` - API response helpers
- `lib/error-handler.ts` - error normalization and handling utilities
- `lib/logger.ts` - application logging helper
- `lib/mock-data.ts` - local mock datasets
- `lib/types.ts` - shared type definitions
- `lib/utils.ts` - general utility helpers
- `lib/validation.ts` - validation helpers and schemas

### Styles and Configuration

- `styles/globals.css` - additional global styles
- `components.json` - UI component generator configuration
- `next.config.mjs` - Next.js configuration
- `postcss.config.mjs` - PostCSS configuration
- `tailwind.config.ts` - Tailwind configuration
- `tsconfig.json` - TypeScript configuration
- `next-env.d.ts` - Next.js type definitions
- `pnpm-lock.yaml` - locked dependency versions
- `package.json` - scripts and dependency manifest
- `.vscode/tasks.json` - VS Code task definitions

## How To Add A New Path

1. Create a new route folder under `app/(dashboard)/<route-name>/page.tsx`.
2. Add the new route to `components/layout/Sidebar.tsx` if it should appear in navigation.
3. Place feature-specific UI in `components/<feature>/` and shared primitives in `components/ui/`.
4. Put reusable logic in `lib/` and custom hooks in `hooks/`.
5. If the page needs shared shell behavior, keep it inside `app/(dashboard)/layout.tsx` rather than duplicating layout code.

## Related Documentation

- `../OTA_IDE_DEV.md`
- `../OTA_IDE_ARCH.md`
- `../OTA_IDE_Details_Task.md`
- `../OTA_README.md`

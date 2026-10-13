import React from 'react';

/**
 * One empty state for the console: an icon in a soft ring, a short title,
 * one line of what to do next, and optionally an action.
 */
export function EmptyState({
  icon,
  title,
  children,
  action,
  compact = false,
}: {
  icon: React.ReactNode;
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={`flex flex-col items-center text-center ${compact ? 'gap-2 py-6' : 'gap-3 py-10'}`}>
      <span
        className="flex items-center justify-center rounded-full"
        style={{
          width: compact ? 40 : 52,
          height: compact ? 40 : 52,
          border: '1px solid var(--app-line)',
          background: 'color-mix(in srgb, var(--ember, #ff2803) 8%, transparent)',
          color: 'var(--ember, #ff2803)',
        }}
        aria-hidden="true"
      >
        {icon}
      </span>
      <p className="text-sm font-semibold text-foreground">{title}</p>
      {children && <p className="max-w-md text-sm text-muted-foreground">{children}</p>}
      {action && <div className="pt-1">{action}</div>}
    </div>
  );
}

/** Placeholder rows while live data loads. */
export function SkeletonRows({ rows = 4, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-3 py-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="flex items-center gap-4">
          {Array.from({ length: columns }, (_, column) => (
            <span
              key={column}
              className="ota-skeleton h-4 rounded"
              style={{ flex: column === 0 ? 2 : 1, animationDelay: `${(row * columns + column) * 40}ms` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

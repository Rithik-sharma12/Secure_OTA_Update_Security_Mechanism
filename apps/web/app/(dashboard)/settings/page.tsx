'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import Link from 'next/link';
import { Settings as SettingsIcon, UserRound, ChevronRight, Sparkles } from 'lucide-react';
import { ACCENTS, ACCENT_KEYS, useAccent, useConsoleLayoutMode, type Accent, type ConsoleLayoutMode } from '@/lib/accent';
import {
  WALLPAPER_COLORS,
  WALLPAPER_STRENGTH,
  WALLPAPER_STYLES,
  useLiveWallpaper,
  useWallpaperColor,
  useWallpaperStrength,
  useWallpaperStyle,
  type WallpaperStrength,
} from '@/components/brand/LiveWallpaper';

/** Pill-shaped single choice, used for the wallpaper options. */
function ChoicePills<T extends string>({
  label,
  options,
  value,
  onChange,
  disabled,
}: {
  label: string;
  options: Record<T, string>;
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className="inline-flex flex-wrap items-center gap-0.5 rounded-lg p-[3px]"
      style={{ border: '1px solid var(--app-line)', opacity: disabled ? 0.5 : 1 }}
    >
      {(Object.keys(options) as T[]).map((key) => {
        const on = key === value;
        return (
          <button
            key={key}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={disabled}
            onClick={() => onChange(key)}
            className="min-h-[30px] rounded-md px-3.5 text-xs font-semibold transition-colors"
            style={{
              background: on ? 'var(--app-inv-bg)' : 'transparent',
              color: on ? 'var(--app-inv-ink)' : 'var(--app-ink2)',
              cursor: disabled ? 'not-allowed' : 'pointer',
            }}
          >
            {options[key]}
          </button>
        );
      })}
    </div>
  );
}

export default function SettingsPage() {
  const [liveWallpaper, setLiveWallpaper] = useLiveWallpaper();
  const [wallpaperStrength, setWallpaperStrength] = useWallpaperStrength();
  const [wallpaperStyle, setWallpaperStyle] = useWallpaperStyle();
  const [wallpaperColor, setWallpaperColor] = useWallpaperColor();
  const [accent, setAccent] = useAccent();
  const [layoutMode, setLayoutMode] = useConsoleLayoutMode();
  const accentLabels = Object.fromEntries(ACCENT_KEYS.map((key) => [key, ACCENTS[key].label])) as Record<Accent, string>;
  const layoutLabels: Record<ConsoleLayoutMode, string> = { framed: 'Framed', full: 'Full width' };
  const strengthLabels = Object.fromEntries(
    (Object.keys(WALLPAPER_STRENGTH) as WallpaperStrength[]).map((key) => [key, WALLPAPER_STRENGTH[key].label])
  ) as Record<WallpaperStrength, string>;
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <SettingsIcon className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          <p className="text-foreground/70 mt-1">Console preferences for this browser</p>
        </div>
      </div>

      <div className="space-y-4">
        {/* Account lives on the profile page; one place for "me". */}
        <Link
          href="/profile"
          className="flex items-center gap-3 rounded-xl border border-border/60 p-4 transition-colors hover:bg-muted/30"
        >
          <span className="rounded-lg bg-primary/15 p-2 text-primary">
            <UserRound className="h-5 w-5" />
          </span>
          <span className="flex-1">
            <span className="block text-sm font-semibold text-foreground">Account and security</span>
            <span className="block text-xs text-muted-foreground">
              Name, photo, password, Google and GitHub sign-in, and signed-in devices are on your profile.
            </span>
          </span>
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        </Link>

        {/* Appearance: per browser, stored locally, no server round trip. */}
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-primary" />
              Appearance
            </CardTitle>
            <CardDescription>Applies to this browser only.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Colour theme</p>
                <p className="text-xs text-foreground/50 mt-1">Buttons, highlights, charts and the background follow it. Works in light and dark.</p>
              </div>
              <ChoicePills label="Colour theme" options={accentLabels} value={accent} onChange={setAccent} />
            </div>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Layout</p>
                <p className="text-xs text-foreground/50 mt-1">Framed floats the console as one rounded panel on large screens.</p>
              </div>
              <ChoicePills label="Layout" options={layoutLabels} value={layoutMode} onChange={setLayoutMode} />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/20 hover:bg-muted/30 transition-colors">
              <div className="flex-1">
                <Label htmlFor="live-wallpaper" className="text-sm font-medium text-foreground cursor-pointer">
                  Animated background
                </Label>
                <p className="text-xs text-foreground/50 mt-1">
                  A slow moving network behind the pages. Always still if your system asks to reduce motion.
                </p>
              </div>
              <Switch id="live-wallpaper" checked={liveWallpaper} onCheckedChange={setLiveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Background strength</p>
                <p className="text-xs text-foreground/50 mt-1">How visible it is behind console pages. Cards stay solid so text stays readable.</p>
              </div>
              <ChoicePills label="Background strength" options={strengthLabels} value={wallpaperStrength} onChange={setWallpaperStrength} disabled={!liveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Scene</p>
                <p className="text-xs text-foreground/50 mt-1">Cycle all fades between the scenes every half minute. Your video plays loop.webm / loop.mp4 from public/backgrounds (format guide in the README there).</p>
              </div>
              <ChoicePills label="Background scene" options={WALLPAPER_STYLES} value={wallpaperStyle} onChange={setWallpaperStyle} disabled={!liveWallpaper} />
            </div>
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-muted/20">
              <div>
                <p className="text-sm font-medium text-foreground">Colour</p>
                <p className="text-xs text-foreground/50 mt-1">Match theme follows the colour theme above; Ember and Cyber blue are fixed.</p>
              </div>
              <ChoicePills label="Background colour" options={WALLPAPER_COLORS} value={wallpaperColor} onChange={setWallpaperColor} disabled={!liveWallpaper} />
            </div>
          </CardContent>
        </Card>

      </div>
    </div>
  );
}

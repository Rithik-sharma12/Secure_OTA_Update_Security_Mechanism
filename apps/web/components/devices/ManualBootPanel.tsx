'use client';

import React from 'react';
import { Hand } from 'lucide-react';

/**
 * Shown while the flasher waits for the person to put the board into the ESP32
 * ROM download mode by hand. Needed on boards without the two-transistor
 * auto-download circuit, and with USB adapters or drivers whose DTR/RTS lines
 * never reach EN and IO0: the automatic reset then just restarts the old
 * firmware, however long BOOT is held.
 */
export function ManualBootPanel({ seconds }: { seconds: number | null }) {
  const [deadline, setDeadline] = React.useState<number | null>(null);
  const [now, setNow] = React.useState(() => Date.now());

  React.useEffect(() => {
    setDeadline(seconds ? Date.now() + seconds * 1000 : null);
  }, [seconds]);

  React.useEffect(() => {
    if (!deadline) return;
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [deadline]);

  if (!deadline) return null;
  const left = Math.max(0, Math.ceil((deadline - now) / 1000));

  return (
    <div role="status" className="rounded-md border border-chart-3/60 bg-chart-3/10 p-3 text-sm">
      <div className="flex items-start gap-3">
        <Hand className="mt-0.5 h-5 w-5 shrink-0 text-chart-3" />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="font-semibold text-foreground">
            Put the board in download mode now <span className="font-normal text-muted-foreground">({left} s left)</span>
          </p>
          <ol className="list-decimal space-y-0.5 pl-5 text-foreground/85">
            <li>Press and hold <strong>BOOT</strong> (also labelled IO0 or FLASH).</li>
            <li>While holding it, press and release <strong>EN</strong> (also labelled RST or RESET).</li>
            <li>Release <strong>BOOT</strong>. Flashing starts on its own within a second.</li>
          </ol>
          <p className="text-xs text-muted-foreground">
            The two buttons sit either side of the USB socket. Holding BOOT alone does nothing: the chip only checks
            BOOT at the moment EN is released.
          </p>
        </div>
      </div>
    </div>
  );
}

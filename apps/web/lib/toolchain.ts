/** Parsing helpers for the arduino-cli toolchain pin (see lib/serial-upload-jobs.ts). */

type CoreListEntry = { id?: string; ID?: string; installed_version?: string; installed?: string; Installed?: string };

export function findInstalledCoreVersion(coreListJson: string, coreId: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(coreListJson);
  } catch {
    return null;
  }
  // arduino-cli >= 0.35 wraps the list in {"platforms": [...]}; older
  // releases print a bare array with `installed` instead of `installed_version`.
  const list: CoreListEntry[] = Array.isArray(parsed)
    ? (parsed as CoreListEntry[])
    : ((parsed as { platforms?: CoreListEntry[] })?.platforms ?? []);
  const entry = list.find((item) => (item.id || item.ID) === coreId);
  return entry ? entry.installed_version || entry.installed || entry.Installed || null : null;
}

import { UnavailablePage } from '@/components/layout/UnavailablePage';

export default function CodePage() {
  return (
    <UnavailablePage
      title="Code"
      reason="The console has no file storage to edit firmware sources in. Build firmware in your own editor, then publish the .bin on the Releases page."
    />
  );
}

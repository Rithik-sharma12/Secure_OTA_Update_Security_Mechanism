import { UnavailablePage } from '@/components/layout/UnavailablePage';

export default function SimulatorPage() {
  return (
    <UnavailablePage
      title="Simulator"
      reason="There is no device simulator behind this console. To test an update, flash a real board on the Devices page and deploy to it."
    />
  );
}

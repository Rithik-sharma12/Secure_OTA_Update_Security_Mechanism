import { UnavailablePage } from '@/components/layout/UnavailablePage';

export default function TcvEnginePage() {
  return (
    <UnavailablePage
      title="TCV Engine"
      reason="The gateway exposes no verification engine settings to configure. Each device's update and verification state is shown on its page under Devices."
    />
  );
}

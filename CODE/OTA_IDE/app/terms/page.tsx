import type { Metadata } from 'next';
import Link from 'next/link';
import { ContactLine, LegalPage } from '@/components/legal/LegalPage';
import { BASE_OPEN_GRAPH, GOVERNING_LAW, LEGAL_ENTITY } from '@/lib/site';
import '../legal.css';

export const metadata: Metadata = {
  title: 'Terms and conditions',
  description: 'The rules for using the SecureOTA website, console and gateway: accounts, acceptable use, your firmware, device risk and liability.',
  alternates: { canonical: '/terms' },
  openGraph: { ...BASE_OPEN_GRAPH, url: '/terms', title: 'SecureOTA terms and conditions' },
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Terms and conditions"
      intro={
        <p>
          These terms govern your use of the SecureOTA website, console and gateway, operated by {LEGAL_ENTITY}. By signing
          in or connecting a device you accept them. If you do not accept them, do not use the service.
        </p>
      }
    >
      <h2>1. The service</h2>
      <p>
        SecureOTA lets you flash boards over USB, publish firmware releases and deliver them to your devices over the
        internet, with verification on each board and automatic rollback when a new build fails its health check.
      </p>

      <h2>2. Your account</h2>
      <ul>
        <li>Keep your sign-in credentials private. You are responsible for everything done with your account.</li>
        <li>Admins of a deployment assign roles. Do not attempt actions your role does not allow.</li>
        <li>Tell us at once if you believe someone else has used your account.</li>
      </ul>

      <h2>3. Acceptable use</h2>
      <p>You agree not to:</p>
      <ul>
        <li>connect, flash or update any device you do not own or are not authorised to manage;</li>
        <li>publish firmware designed to damage devices, steal data or attack other systems;</li>
        <li>probe, overload or bypass the security of the console, the gateway or any connected device;</li>
        <li>use the service in breach of any law that applies to you or to the devices you manage.</li>
      </ul>
      <p>We may suspend an account that breaks these rules.</p>

      <h2>4. Your firmware and data</h2>
      <p>
        You keep ownership of the firmware, configuration and device data you put into SecureOTA. You give us permission to
        store, process and deliver it only as needed to run the service for you. How we handle personal data is set out
        in the <Link href="/privacy">privacy policy</Link>.
      </p>

      <h2>5. Device risk</h2>
      <p>
        Updating firmware changes the software a device runs. SecureOTA verifies each image and rolls a board back when a
        new build cannot reach the gateway, but no safeguard covers every fault. A build can pass its health check and
        still behave incorrectly, and hardware, power or network failures during an update can leave a device that needs
        a manual reflash. Test every release on a representative device before you deploy it to a fleet.
      </p>

      <h2>6. Availability and changes</h2>
      <p>
        We provide the service as it is and as available. We may change, pause or end any part of it. We aim to give
        notice of significant changes, but we do not guarantee uninterrupted access.
      </p>

      <h2>7. Limitation of liability</h2>
      <p>
        To the extent the law allows, {LEGAL_ENTITY} is not liable for indirect or consequential loss, lost data, lost
        profit, or damage to devices arising from your use of the service. Nothing in these terms limits liability that
        cannot be limited by law.
      </p>

      <h2>8. Ending your use</h2>
      <p>
        You can stop using SecureOTA at any time and ask us to delete your account. We may close an account that breaks
        these terms. Sections 4, 5 and 7 continue to apply after your account ends.
      </p>

      <h2>9. Governing law</h2>
      <p>These terms are governed by the laws of {GOVERNING_LAW}.</p>

      <h2>10. Contact</h2>
      <p>
        For questions about these terms, <ContactLine />.
      </p>
    </LegalPage>
  );
}

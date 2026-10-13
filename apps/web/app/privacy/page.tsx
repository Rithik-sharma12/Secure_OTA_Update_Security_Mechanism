import type { Metadata } from 'next';
import { ContactLine, LegalPage } from '@/components/legal/LegalPage';
import { BASE_OPEN_GRAPH, LEGAL_ENTITY, SITE_URL } from '@/lib/site';
import '../legal.css';

export const metadata: Metadata = {
  title: 'Privacy policy',
  description: 'What SecureOTA collects when you sign in and connect devices, why, who processes it, how long it is kept and how to have it removed.',
  alternates: { canonical: '/privacy' },
  openGraph: { ...BASE_OPEN_GRAPH, url: '/privacy', title: 'SecureOTA privacy policy' },
};

/**
 * Every statement here describes what the code does today:
 * - accounts: lib/auth.ts (Clerk profile sync), lib/local-database.ts
 * - Supabase copy: lib/supabase-sync.ts (only when its keys are set)
 * - audit trail and telemetry: apps/gateway/gateway/history.py
 *   (OTA_TELEMETRY_RETENTION_DAYS = 7, OTA_AUDIT_MAX_ROWS = 50000 by default)
 * Change this page whenever one of those changes.
 */
export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacy policy"
      intro={
        <p>
          This policy covers the SecureOTA website and console at {SITE_URL.replace(/^https?:\/\//, '')}, operated by{' '}
          {LEGAL_ENTITY}. It lists what we collect, why we collect it, who handles it for us and how long we keep it.
        </p>
      }
    >
      <h2>What we collect</h2>
      <h3>Your account</h3>
      <p>
        You sign in through Clerk, our authentication provider, with Google, GitHub or an e-mail address and password.
        Clerk passes us your name, e-mail address, profile photo and the sign-in methods you use. We store those with
        your console role (viewer, operator or admin) and the time you last signed in. We never receive your Google or
        GitHub password.
      </p>
      <h3>Sign-in sessions</h3>
      <p>
        A session cookie keeps you signed in. Clerk sets its own cookies for the same purpose. We store only a hash of
        each session token, never the token itself.
      </p>
      <h3>What you do in the console</h3>
      <ul>
        <li>
          An audit trail of every change made through the gateway: the account, the source IP address, the action, the
          device involved and the result. Refused requests are recorded too.
        </li>
        <li>A request log for the console: the page or API route, the result, how long it took and the account.</li>
        <li>
          Firmware you publish or flash: file name, SHA-256 digest, board type, serial port and the outcome of each job.
        </li>
      </ul>
      <h3>Devices you connect</h3>
      <p>
        Each board reports its device ID, firmware version, health score, Wi-Fi signal strength, memory, CPU load and
        uptime. The Wi-Fi password you enter while setting up a board is written to the board. It is not stored in our
        logs or job records.
      </p>
      <h3>Your browser</h3>
      <p>
        We keep your display preferences (light or dark mode, colour theme, layout) and your signed-in profile in your
        browser&apos;s local storage. They stay on your device.
      </p>

      <h2>Why we collect it</h2>
      <ul>
        <li>To sign you in and apply the permissions of your role.</li>
        <li>To deliver firmware to your devices and show you their state.</li>
        <li>To keep the service secure: the audit trail shows who changed what and catches repeated failed attempts.</li>
        <li>To find and fix faults.</li>
      </ul>
      <p>We do not sell your data. We do not show advertising. We do not run third-party tracking.</p>

      <h2>Who handles it for us</h2>
      <ul>
        <li>
          <strong>Clerk</strong> runs sign-in and holds your account profile.
        </li>
        <li>
          <strong>Supabase</strong> stores a copy of account profiles and firmware job records when the operator enables it.
        </li>
        <li>
          <strong>Cloudflare</strong> carries traffic to the site when it is published through a Cloudflare Tunnel.
        </li>
        <li>
          <strong>Vercel</strong> counts page views without cookies, only when the site is hosted on Vercel.
        </li>
      </ul>
      <p>Each provider processes data under its own terms and only to deliver its part of the service.</p>

      <h2>How long we keep it</h2>
      <ul>
        <li>Account details: until you ask us to delete your account.</li>
        <li>Sign-in sessions: they expire automatically.</li>
        <li>Device health readings: 7 days.</li>
        <li>Audit trail: the most recent 50,000 entries. Older entries are deleted automatically.</li>
      </ul>

      <h2>Your rights</h2>
      <p>
        You can ask for a copy of your data, ask us to correct it, or ask us to delete your account and the records tied to
        it. To make a request, <ContactLine />. Do not put personal details in a public issue. Ask for a private channel
        and we will reply there.
      </p>

      <h2>Security</h2>
      <p>
        Traffic to the site is encrypted when it is served over HTTPS. Session tokens are stored as hashes. Firmware is
        verified on each board before it is written. No system is perfectly secure, so tell us at once if you find a
        weakness.
      </p>

      <h2>Children</h2>
      <p>SecureOTA is a tool for engineering teams. It is not directed at children.</p>

      <h2>Changes to this policy</h2>
      <p>
        When we change this policy we update this page and the date at the top.
      </p>
    </LegalPage>
  );
}

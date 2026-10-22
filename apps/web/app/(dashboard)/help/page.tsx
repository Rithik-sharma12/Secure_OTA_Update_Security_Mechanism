import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Book, ChevronDown, ExternalLink, Github, HelpCircle, Mail } from 'lucide-react';
import { CONTACT_EMAIL, SOURCE_REPOSITORY } from '@/lib/site';

const DOCS = `${SOURCE_REPOSITORY}/blob/main/docs`;

const faqs = [
  {
    question: 'How do I update device firmware?',
    answer:
      'Publish the compiled .bin on the Releases page, then create a deployment for the devices on the Deployments page. Each device picks up the assignment on its next heartbeat, and the deployment marks it confirmed only when the device reports the new version.',
  },
  {
    question: 'What devices are supported?',
    answer:
      'Releases can target ESP32, ESP8266, STM32F103 and ATmega328P, and the gateway only offers a release to the architectures it lists. The firmware in this repository is written for the ESP32.',
  },
  {
    question: 'Can I roll a device back to an older version?',
    answer:
      'No. The gateway refuses to deploy a version older than the one a device already runs (anti-rollback). A device that boots a new image and fails its health check returns to its previous image on its own.',
  },
  {
    question: 'Where are the signing keys?',
    answer:
      'The gateway creates its Ed25519 signing key the first time it starts and signs every manifest with it. The Key Vault page shows the key and its public half; the console cannot create or replace keys.',
  },
  {
    question: 'How do I view device logs?',
    answer:
      'Event Logs lists gateway events together with the last log lines each device sent with its heartbeat. Open a device on the Devices page for its own history and commands.',
  },
];

const resources = [
  { title: 'How to run', description: 'Running locally and online, step by step.', href: `${DOCS}/how-to-run.md` },
  { title: 'End-to-end demo', description: 'From firmware build to a confirmed OTA update.', href: `${DOCS}/guides/END_TO_END_DEMO.md` },
  { title: 'Updating from the web console', description: 'Publishing, deploying and flashing from this console.', href: `${DOCS}/guides/WEB_OTA_UPDATE_GUIDE.md` },
  { title: 'Remote commands and USB provisioning', description: 'Device commands and first-time USB setup.', href: `${DOCS}/guides/REMOTE_OTA_AND_USB_PROVISIONING.md` },
  { title: 'Architecture', description: 'System and protocol design.', href: `${DOCS}/architecture/OTA_ARCHITECTURE.md` },
  { title: 'Docker deployment', description: 'Running the stack with Docker Compose.', href: `${DOCS}/guides/DOCKER_DEPLOYMENT.md` },
];

export default function HelpPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="rounded-lg bg-accent/20 p-3 text-accent">
          <HelpCircle className="h-6 w-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Help</h1>
          <p className="mt-1 text-foreground/70">Answers to common questions and the project documentation.</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Frequently asked questions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {faqs.map((faq) => (
            <details key={faq.question} className="group rounded-lg border border-border/20 p-4 hover:bg-muted/10">
              <summary className="flex cursor-pointer items-center justify-between font-semibold text-foreground">
                <span>{faq.question}</span>
                <ChevronDown className="h-5 w-5 flex-shrink-0 text-primary transition-transform group-open:rotate-180" />
              </summary>
              <p className="mt-3 text-sm leading-relaxed text-foreground/70">{faq.answer}</p>
            </details>
          ))}
        </CardContent>
      </Card>

      <div>
        <h2 className="mb-4 text-lg font-semibold text-foreground">Documentation</h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {resources.map((resource) => (
            <a key={resource.title} href={resource.href} target="_blank" rel="noopener noreferrer" className="group block">
              <Card className="h-full transition-all group-hover:border-primary/50">
                <CardContent className="pt-6">
                  <div className="mb-3 flex items-start justify-between">
                    <Book className="h-5 w-5 text-primary" />
                    <ExternalLink className="h-4 w-4 text-primary/40" />
                  </div>
                  <p className="font-semibold text-foreground">{resource.title}</p>
                  <p className="mt-2 text-xs text-foreground/60">{resource.description}</p>
                </CardContent>
              </Card>
            </a>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Still stuck?</CardTitle>
          <CardDescription>Report a problem or ask a question on the project&apos;s issue tracker.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button asChild>
            <a href={`${SOURCE_REPOSITORY}/issues`} target="_blank" rel="noopener noreferrer">
              <Github className="mr-2 h-4 w-4" />
              Open an issue
            </a>
          </Button>
          <Button asChild variant="outline">
            <a href={`${DOCS}/README.md`} target="_blank" rel="noopener noreferrer">
              <Book className="mr-2 h-4 w-4" />
              All documentation
            </a>
          </Button>
          {CONTACT_EMAIL && (
            <Button asChild variant="outline">
              <a href={`mailto:${CONTACT_EMAIL}`}>
                <Mail className="mr-2 h-4 w-4" />
                {CONTACT_EMAIL}
              </a>
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

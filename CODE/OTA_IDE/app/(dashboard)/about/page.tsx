import Image from 'next/image';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  BookOpen,
  CheckCircle2,
  Clock3,
  Cog,
  Factory,
  Lightbulb,
  MapPin,
  Rocket,
  ShieldCheck,
  Target,
  Users,
  Wrench,
} from 'lucide-react';

const developers = [
  {
    name: 'Rithik Sharma',
    role: 'System Architecture and OTA Security Pipeline',
    bio: 'Designed the end-to-end trust flow and integrated release automation with secure firmware validation.',
    image: '/developers/rithik-sharma.svg',
  },
  {
    name: 'Priyankaa Devi S',
    role: 'Embedded Security and Device Validation',
    bio: 'Focused on constrained-device verification logic, rollback safety, and field-ready firmware behavior.',
    image: '/developers/priyankaa-devi-s.svg',
  },
  {
    name: 'Ritesh V',
    role: 'Release Engineering and Platform Integration',
    bio: 'Implemented practical release workflows, operational tooling, and dashboard-driven update management.',
    image: '/developers/ritesh-v.svg',
  },
];

const fiveWOneH = [
  {
    title: 'What',
    icon: BookOpen,
    text: 'A secure heterogeneous OTA update platform for IoT fleets that verifies firmware authenticity before install and supports safer release operations.',
  },
  {
    title: 'Why',
    icon: Lightbulb,
    text: 'Traditional OTA setups are expensive, error-prone, and often insecure for low-cost devices. This project closes that gap with practical security and developer automation.',
  },
  {
    title: 'When',
    icon: Clock3,
    text: 'Built for continuous delivery cycles where firmware changes happen regularly and reliability is critical, including incident response or urgent patch windows.',
  },
  {
    title: 'Where',
    icon: MapPin,
    text: 'Applicable in smart manufacturing, campus infrastructure, industrial monitoring, and any environment running mixed microcontroller fleets.',
  },
  {
    title: 'How',
    icon: Cog,
    text: 'By combining CI/CD releases, signed firmware artifacts, manifest validation, and dashboard-led deployment controls with device-side verification and rollback protection.',
  },
];

const workflowSteps = [
  'Developer tags or pushes firmware changes to the repository.',
  'CI/CD builds the firmware, creates release artifacts, and signs metadata.',
  'Manifest and binary artifacts are published to the release channel.',
  'The OTA IDE dashboard detects and displays releasable versions.',
  'Operator selects target devices or groups and starts deployment.',
  'Each device validates signature and integrity before flashing.',
  'On validation failure, update is rejected and device remains safe.',
  'On success, telemetry and logs are recorded for audit and diagnostics.',
];

const beginnerWalkthrough = [
  {
    step: 'Step 1: Prepare Environment',
    detail:
      'Run the OTA IDE, log in, and verify your devices appear in Devices. Confirm each device has network access and the expected board profile.',
  },
  {
    step: 'Step 2: Build a Release',
    detail:
      'Create or update firmware code, then trigger your release process. The system should produce versioned artifacts and a signed manifest.',
  },
  {
    step: 'Step 3: Validate in Dashboard',
    detail:
      'Open Releases and Manifest pages to verify the new version metadata, hash references, and deployment readiness before targeting production devices.',
  },
  {
    step: 'Step 4: Deploy Safely',
    detail:
      'Use Pipeline or Releases to select a staged rollout strategy. Start with a small pilot batch, then expand to full fleet after healthy telemetry.',
  },
  {
    step: 'Step 5: Observe and Iterate',
    detail:
      'Monitor Event Logs, Dashboard metrics, and Diagnostics. If a failure appears, pause rollout, inspect logs, fix firmware, and redeploy confidently.',
  },
];

const star = {
  situation:
    'A mixed fleet of ESP32 and STM32 edge devices required frequent firmware updates, but manual release handling caused version drift and security concerns.',
  task:
    'Create a secure, repeatable update process that non-specialist operators could use while still satisfying engineering and governance requirements.',
  action:
    'Implemented signed release artifacts, manifest verification, dashboard-assisted rollout, and runtime diagnostics. Added clear release views and operational controls for controlled deployment.',
  result:
    'Updates became traceable and safer. Engineers gained predictable release flow, operators gained confidence through guided workflows, and stakeholders gained better reliability visibility.',
};

export default function AboutPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 rounded-lg bg-accent/20 text-accent">
          <Users className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">About This Project</h1>
          <p className="text-foreground/70 mt-1">
            A technical overview for engineers, users, and industry stakeholders
          </p>
        </div>
      </div>

      <Card className="glass border-accent/30 bg-gradient-to-br from-accent/10 to-transparent">
        <CardHeader>
          <CardTitle className="text-2xl">Secure Heterogeneous OTA Update Mechanism</CardTitle>
          <CardDescription>
            This platform is designed to deliver trustworthy firmware updates across different IoT device families while reducing operational friction.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge className="bg-chart-1/20 text-chart-1">Security-First OTA</Badge>
          <Badge className="bg-primary/20 text-primary">Heterogeneous Devices</Badge>
          <Badge className="bg-chart-3/20 text-chart-3">CI/CD Integrated</Badge>
          <Badge className="bg-chart-2/20 text-chart-2">Operator-Friendly</Badge>
        </CardContent>
      </Card>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">Developers</h2>
        <p className="text-sm text-foreground/70">
          Core contributors who built and shaped this OTA platform.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {developers.map((developer) => (
            <Card key={developer.name} className="glass border-border/50 hover:border-primary/40 transition-all">
              <CardContent className="pt-6">
                <div className="mb-4 overflow-hidden rounded-xl border border-border/40 bg-muted/20">
                  <Image
                    src={developer.image}
                    alt={`${developer.name} profile`}
                    width={720}
                    height={720}
                    className="h-52 w-full object-cover"
                    priority={false}
                  />
                </div>
                <h3 className="text-lg font-semibold text-foreground">{developer.name}</h3>
                <p className="text-sm text-primary mt-1">{developer.role}</p>
                <p className="text-sm text-foreground/70 mt-3 leading-relaxed">{developer.bio}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">Project Explained: What, Why, When, Where, How</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {fiveWOneH.map((entry) => {
            const Icon = entry.icon;
            return (
              <Card key={entry.title} className="glass border-border/50 hover:border-border/80 transition-all">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="rounded-lg p-2 bg-primary/15 text-primary">
                      <Icon className="w-5 h-5" />
                    </div>
                    <h3 className="text-lg font-semibold text-foreground">{entry.title}</h3>
                  </div>
                  <p className="text-sm text-foreground/75 leading-relaxed">{entry.text}</p>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">How It Works End-to-End</h2>
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardContent className="pt-6">
            <ol className="space-y-3">
              {workflowSteps.map((step, index) => (
                <li key={step} className="flex items-start gap-3 rounded-lg border border-border/20 bg-muted/10 p-3">
                  <span className="mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-semibold text-primary">
                    {index + 1}
                  </span>
                  <p className="text-sm text-foreground/80 leading-relaxed">{step}</p>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">Beginner Walkthrough</h2>
        <p className="text-sm text-foreground/70">
          A practical starter path for first-time users and student teams.
        </p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {beginnerWalkthrough.map((item) => (
            <Card key={item.step} className="glass border-border/50 hover:border-primary/40 transition-all">
              <CardContent className="pt-6">
                <h3 className="text-base font-semibold text-foreground">{item.step}</h3>
                <p className="text-sm text-foreground/75 mt-2 leading-relaxed">{item.detail}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">Project Example Using STAR Method</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Target className="w-5 h-5 text-primary" />
                Situation
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-foreground/75 leading-relaxed">{star.situation}</p>
            </CardContent>
          </Card>

          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Wrench className="w-5 h-5 text-primary" />
                Task
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-foreground/75 leading-relaxed">{star.task}</p>
            </CardContent>
          </Card>

          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary" />
                Action
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-foreground/75 leading-relaxed">{star.action}</p>
            </CardContent>
          </Card>

          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-primary" />
                Result
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-foreground/75 leading-relaxed">{star.result}</p>
            </CardContent>
          </Card>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold text-foreground">Why This Matters for Different Stakeholders</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="glass border-border/50">
            <CardContent className="pt-6">
              <h3 className="font-semibold text-foreground mb-2">Engineers</h3>
              <p className="text-sm text-foreground/75 leading-relaxed">
                Faster and safer release cycles with traceable artifacts, better diagnostics, and reproducible deployment pipelines.
              </p>
            </CardContent>
          </Card>

          <Card className="glass border-border/50">
            <CardContent className="pt-6">
              <h3 className="font-semibold text-foreground mb-2">Users and Operators</h3>
              <p className="text-sm text-foreground/75 leading-relaxed">
                Guided workflows, reduced update failures, clearer operational visibility, and confidence in firmware authenticity.
              </p>
            </CardContent>
          </Card>

          <Card className="glass border-border/50">
            <CardContent className="pt-6">
              <h3 className="font-semibold text-foreground mb-2">Industry and Business</h3>
              <p className="text-sm text-foreground/75 leading-relaxed">
                Lower security risk, better compliance posture, and scalable fleet operations without expensive bespoke OTA infrastructure.
              </p>
            </CardContent>
          </Card>
        </div>
      </section>

      <Card className="glass border-primary/30 bg-gradient-to-r from-primary/10 to-accent/10">
        <CardContent className="pt-8 pb-8 text-center">
          <div className="mx-auto max-w-3xl">
            <div className="mb-3 inline-flex rounded-full bg-primary/20 p-2 text-primary">
              <Rocket className="h-5 w-5" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">From Blog to Production Workflow</h2>
            <p className="text-sm text-foreground/75 mt-3 leading-relaxed">
              This About page is intentionally written as a technical blog so both engineering and non-engineering audiences can understand the value, operation, and rollout journey of the platform.
            </p>
            <p className="text-sm text-foreground/75 mt-2 leading-relaxed">
              Use it as your onboarding reference, stakeholder briefing document, and implementation narrative for practical secure OTA deployments.
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              <Badge className="bg-chart-1/20 text-chart-1">
                <Factory className="h-3.5 w-3.5 mr-1" /> Operationally Ready
              </Badge>
              <Badge className="bg-chart-2/20 text-chart-2">
                <Users className="h-3.5 w-3.5 mr-1" /> Beginner Friendly
              </Badge>
              <Badge className="bg-chart-3/20 text-chart-3">
                <ShieldCheck className="h-3.5 w-3.5 mr-1" /> Security Focused
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

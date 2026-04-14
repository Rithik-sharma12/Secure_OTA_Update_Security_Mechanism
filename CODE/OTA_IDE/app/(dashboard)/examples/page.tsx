import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  GitBranch,
  ShieldCheck,
  Terminal,
  Users,
} from 'lucide-react';

const examples = [
  {
    title: 'Example 1: Staged Rollout for 100 Devices',
    goal: 'Deploy firmware safely with low blast radius.',
    steps: [
      'Create release v2.6.0 and validate manifest metadata.',
      'Deploy to pilot group of 10 devices.',
      'Observe runtime telemetry and event logs for 15 minutes.',
      'Expand to 40 devices if pilot remains healthy.',
      'Complete rollout to all 100 devices after checks pass.',
    ],
    result: 'Higher confidence rollouts with early detection of edge-case failures.',
    icon: GitBranch,
  },
  {
    title: 'Example 2: Emergency Security Patch',
    goal: 'Ship a critical fix rapidly while preserving trust.',
    steps: [
      'Tag hotfix release and publish signed artifacts.',
      'Prioritize internet-facing devices first.',
      'Apply deployment windows by region to avoid overload.',
      'Track failed verification events and isolate affected cohorts.',
      'Rollback specific cohorts if validation anomalies increase.',
    ],
    result: 'Fast mitigation with controlled operational risk.',
    icon: ShieldCheck,
  },
  {
    title: 'Example 3: First-Time Site Onboarding',
    goal: 'Bring a new device cluster online with guided checks.',
    steps: [
      'Register device metadata and connectivity baseline.',
      'Run simulator-driven dry run for configuration validation.',
      'Deploy stable baseline firmware to onboarding group.',
      'Confirm heartbeat, diagnostics, and event visibility.',
      'Enable routine release channel after acceptance criteria.',
    ],
    result: 'Predictable onboarding and fewer production surprises.',
    icon: Users,
  },
];

const apiExample = `POST /api/runtime/actions
Content-Type: application/json

{
  "action": "releases.deploy",
  "payload": {
    "version": "v2.6.0",
    "targetGroup": "pilot-group-a",
    "strategy": "staged"
  }
}`;

const terminalExample = `# Build and run OTA IDE locally
cd CODE/OTA_IDE
npm install
npm run dev

# Open dashboard
# http://localhost:3000`;

export default function ExamplesPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <FlaskConical className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Project Examples</h1>
          <p className="text-foreground/70 mt-1">
            Practical examples for engineers, operators, and stakeholders
          </p>
        </div>
      </div>

      <Card className="glass border-primary/30 bg-gradient-to-r from-primary/10 to-transparent">
        <CardHeader>
          <CardTitle>How to Use This Page</CardTitle>
          <CardDescription>
            Start with the scenario that matches your current stage: rollout, incident patching, or onboarding.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Badge className="bg-chart-1/20 text-chart-1">Beginner Friendly</Badge>
          <Badge className="bg-chart-2/20 text-chart-2">Operations Ready</Badge>
          <Badge className="bg-chart-3/20 text-chart-3">Security Focused</Badge>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {examples.map((example) => {
          const Icon = example.icon;

          return (
            <Card key={example.title} className="glass border-border/50 hover:border-primary/40 transition-all">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Icon className="w-5 h-5 text-primary" />
                  {example.title}
                </CardTitle>
                <CardDescription>{example.goal}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-foreground/60 mb-2">Steps</p>
                  <ol className="space-y-2">
                    {example.steps.map((step, index) => (
                      <li key={step} className="flex items-start gap-2 text-sm text-foreground/80">
                        <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/20 text-xs font-semibold text-primary">
                          {index + 1}
                        </span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                <div className="rounded-lg border border-chart-1/30 bg-chart-1/10 p-3 text-sm text-foreground/80">
                  <span className="font-semibold text-chart-1">Expected Result:</span> {example.result}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-primary" />
              Terminal Run Example
            </CardTitle>
            <CardDescription>Quick local run sequence for contributors.</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-lg border border-border/40 bg-muted/30 p-3 text-xs text-foreground/85">
{terminalExample}
            </pre>
          </CardContent>
        </Card>

        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-primary" />
              API Action Example
            </CardTitle>
            <CardDescription>Sample payload for release deployment automation.</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto rounded-lg border border-border/40 bg-muted/30 p-3 text-xs text-foreground/85">
{apiExample}
            </pre>
          </CardContent>
        </Card>
      </div>

      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-chart-3" />
            Common Mistakes to Avoid
          </CardTitle>
          <CardDescription>Short checklist before every deployment wave.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2 text-sm text-foreground/80">
            <li>- Skipping pilot rollout for urgent updates.</li>
            <li>- Deploying without checking manifest and release metadata.</li>
            <li>- Ignoring runtime snapshot anomalies during staged rollout.</li>
            <li>- Running full-fleet deployment without rollback readiness.</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

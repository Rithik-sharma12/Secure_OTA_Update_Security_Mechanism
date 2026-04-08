'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ChevronDown, HelpCircle, Book, Mail, MessageSquare, Github, ExternalLink } from 'lucide-react';

const faqs = [
  {
    question: 'How do I update device firmware?',
    answer: 'Navigate to Devices, select the device, and click "Update Firmware". Choose the target version and confirm. You can schedule the update for a specific time or deploy immediately.',
  },
  {
    question: 'What devices are supported?',
    answer: 'OTA IDE supports ATmega328P, ESP8266, ESP32, and STM32F103 microcontrollers. Check device compatibility in the Devices section.',
  },
  {
    question: 'How can I schedule deployments?',
    answer: 'Use the Pipeline section to create deployment schedules with specific timing and device targeting. You can set up automatic deployments based on version releases.',
  },
  {
    question: 'How do I manage encryption keys?',
    answer: 'Access the Key Vault section to generate, store, and manage cryptographic keys and certificates. All keys are encrypted at rest.',
  },
  {
    question: 'Can I rollback a failed deployment?',
    answer: 'Yes, navigate to Releases and select a previous version. Click "Rollback" to revert devices to that firmware version.',
  },
  {
    question: 'How do I view device logs?',
    answer: 'Go to Event Logs to see all device events. Filter by device, severity, or time range. Logs are retained for 90 days.',
  },
];

const resources = [
  { 
    title: 'API Documentation', 
    description: 'Complete API reference and integration guides',
    icon: <Book className="w-5 h-5" />
  },
  { 
    title: 'Getting Started Guide', 
    description: 'Step-by-step setup and first deployment',
    icon: <HelpCircle className="w-5 h-5" />
  },
  { 
    title: 'Best Practices', 
    description: 'Firmware deployment strategies and optimization',
    icon: <MessageSquare className="w-5 h-5" />
  },
  { 
    title: 'Troubleshooting', 
    description: 'Common issues and solutions',
    icon: <MessageSquare className="w-5 h-5" />
  },
  { 
    title: 'GitHub Repository', 
    description: 'Source code and examples',
    icon: <Github className="w-5 h-5" />
  },
  { 
    title: 'Contact Support', 
    description: 'Email support@ota-ide.example.com',
    icon: <Mail className="w-5 h-5" />
  },
];

export default function HelpPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-accent/20 text-accent">
          <HelpCircle className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Help & Documentation</h1>
          <p className="text-foreground/70 mt-1">Guides, FAQs, and support resources</p>
        </div>
      </div>

      {/* Quick Support */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Documentation', time: 'Visit now', icon: <Book className="w-5 h-5" /> },
          { label: 'Live Chat', time: '5 min response', icon: <MessageSquare className="w-5 h-5" /> },
          { label: 'Email Support', time: '24h response', icon: <Mail className="w-5 h-5" /> },
        ].map((support) => (
          <Card key={support.label} className="glass border-border/50 hover:border-accent/50 transition-all cursor-pointer group">
            <CardContent className="pt-6">
              <div className="flex items-start gap-3 mb-3">
                <div className="text-accent group-hover:text-accent/80 transition-colors">{support.icon}</div>
              </div>
              <p className="font-semibold text-foreground group-hover:text-accent transition-colors">{support.label}</p>
              <p className="text-xs text-foreground/60 mt-1">{support.time}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* FAQ Section */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Frequently Asked Questions</CardTitle>
          <CardDescription>Find quick answers to common questions</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {faqs.map((faq, i) => (
            <details key={i} className="group border border-border/20 rounded-lg p-4 cursor-pointer hover:bg-muted/10 transition-colors">
              <summary className="flex items-center justify-between font-semibold text-foreground">
                <span>{faq.question}</span>
                <ChevronDown className="w-5 h-5 group-open:rotate-180 transition-transform text-primary flex-shrink-0" />
              </summary>
              <p className="mt-3 text-sm text-foreground/70 leading-relaxed">{faq.answer}</p>
            </details>
          ))}
        </CardContent>
      </Card>

      {/* Resources Grid */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Learning Resources</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {resources.map((resource) => (
            <Card key={resource.title} className="glass border-border/50 hover:border-primary/50 transition-all group cursor-pointer">
              <CardContent className="pt-6">
                <div className="flex items-start justify-between mb-3">
                  <div className="text-primary group-hover:text-accent transition-colors">{resource.icon}</div>
                  <ExternalLink className="w-4 h-4 text-primary/40 group-hover:text-accent transition-colors" />
                </div>
                <p className="font-semibold text-foreground group-hover:text-primary transition-colors">{resource.title}</p>
                <p className="text-xs text-foreground/60 mt-2">{resource.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Knowledge Base */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Knowledge Base Topics</CardTitle>
          <CardDescription>Explore detailed guides on specific topics</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              { title: 'Getting Started', topics: ['Installation', 'Configuration', 'First Deployment'] },
              { title: 'Device Management', topics: ['Adding Devices', 'Monitoring Health', 'Troubleshooting'] },
              { title: 'Deployments', topics: ['Creating Releases', 'Scheduling Updates', 'Rollback'] },
              { title: 'Security', topics: ['Key Management', 'Certificate Setup', 'Authentication'] },
              { title: 'API Integration', topics: ['REST API', 'Webhooks', 'Rate Limiting'] },
              { title: 'Advanced Topics', topics: ['Custom Pipelines', 'Analytics', 'Automation'] },
            ].map((category) => (
              <div key={category.title} className="p-4 rounded-lg bg-muted/20 border border-border/20 hover:border-border/40 transition-colors">
                <p className="font-semibold text-foreground mb-2">{category.title}</p>
                <ul className="space-y-1">
                  {category.topics.map((topic) => (
                    <li key={topic} className="text-sm text-foreground/70 hover:text-primary transition-colors cursor-pointer ml-2">
                      • {topic}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Support Contact */}
      <Card className="glass border-accent/20 hover:border-accent/50 transition-all bg-gradient-to-br from-accent/5 to-transparent">
        <CardContent className="pt-8 pb-8">
          <div className="text-center max-w-2xl mx-auto">
            <h3 className="text-2xl font-bold text-foreground mb-2">Can&apos;t find what you&apos;re looking for?</h3>
            <p className="text-foreground/70 mb-6">Our support team is here to help. Reach out via any of these channels.</p>
            <div className="flex gap-2 justify-center flex-wrap">
              <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
                <Mail className="w-4 h-4 mr-2" />
                Email Support
              </Button>
              <Button variant="outline" className="border-border">
                <MessageSquare className="w-4 h-4 mr-2" />
                Live Chat
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

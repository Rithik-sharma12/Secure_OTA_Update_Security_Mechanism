'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Download, Plus, Eye, BarChart3, FileText, TrendingUp, Calendar } from 'lucide-react';

const reports = [
  { 
    title: 'Monthly Device Health Report', 
    date: 'Mar 2024', 
    status: 'generated', 
    format: 'PDF',
    size: '2.4 MB',
    icon: <BarChart3 className="w-5 h-5 text-accent" />
  },
  { 
    title: 'Deployment Summary & Analytics', 
    date: 'Feb 2024', 
    status: 'generated', 
    format: 'CSV',
    size: '156 KB',
    icon: <TrendingUp className="w-5 h-5 text-primary" />
  },
  { 
    title: 'Security Audit & Compliance', 
    date: 'Jan 2024', 
    status: 'generating', 
    format: 'PDF',
    size: '--',
    icon: <FileText className="w-5 h-5 text-yellow-500" />
  },
  { 
    title: 'Device Performance Baseline', 
    date: 'Dec 2023', 
    status: 'generated', 
    format: 'PDF',
    size: '3.1 MB',
    icon: <BarChart3 className="w-5 h-5 text-accent" />
  },
];

const reportTypes = [
  { name: 'Device Health', description: 'Comprehensive device status and metrics' },
  { name: 'Deployment', description: 'Firmware update and deployment history' },
  { name: 'Security', description: 'Security audit and compliance report' },
  { name: 'Performance', description: 'System performance analysis and trends' },
];

export default function ReportsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-accent/20 text-accent">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Reports</h1>
            <p className="text-foreground/70 mt-1">Generate and manage comprehensive system reports</p>
          </div>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
          <Plus className="w-4 h-4 mr-2" />
          Generate New Report
        </Button>
      </div>

      {/* Report Templates */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Report Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {reportTypes.map((type) => (
            <Card key={type.name} className="glass border-border/50 hover:border-primary/50 transition-all cursor-pointer group">
              <CardContent className="pt-6">
                <div className="space-y-3">
                  <p className="font-semibold text-foreground group-hover:text-primary transition-colors">{type.name}</p>
                  <p className="text-sm text-foreground/60">{type.description}</p>
                  <Button size="sm" variant="outline" className="w-full border-border text-xs">
                    Create
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Generated Reports */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Generated Reports</h2>
        <div className="grid grid-cols-1 gap-4">
          {reports.map((report, i) => (
            <Card key={i} className="glass border-border/50 hover:border-border/80 transition-all group">
              <CardContent className="pt-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-4 flex-1">
                    <div className="mt-1">
                      {report.icon}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors">{report.title}</h3>
                      <div className="flex items-center gap-3 mt-2 text-sm text-foreground/60 flex-wrap">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {report.date}
                        </div>
                        <Badge variant="outline" className={`text-xs ${
                          report.status === 'generated' 
                            ? 'bg-chart-1/20 text-chart-1'
                            : 'bg-chart-3/20 text-chart-3'
                        }`}>
                          {report.status}
                        </Badge>
                        <span className="text-xs">{report.format}</span>
                        {report.size !== '--' && <span className="text-xs text-foreground/40">{report.size}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <Button size="sm" variant="outline" className="border-border whitespace-nowrap">
                      <Eye className="w-4 h-4 mr-2" />
                      View
                    </Button>
                    <Button size="sm" variant="outline" className="border-border whitespace-nowrap">
                      <Download className="w-4 h-4 mr-2" />
                      Download
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Scheduled Reports */}
      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle>Scheduled Reports</CardTitle>
          <CardDescription>Reports that are automatically generated on a schedule</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { name: 'Monthly Health Report', schedule: 'First day of each month at 2:00 AM', next: 'Apr 1, 2024' },
              { name: 'Weekly Deployment Summary', schedule: 'Every Sunday at 6:00 PM', next: 'Mar 17, 2024' },
            ].map((scheduled) => (
              <div key={scheduled.name} className="p-3 rounded-lg bg-muted/20 border border-border/20 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">{scheduled.name}</p>
                  <p className="text-xs text-foreground/60 mt-1">{scheduled.schedule}</p>
                  <p className="text-xs text-foreground/50 mt-1">Next: {scheduled.next}</p>
                </div>
                <Button size="sm" variant="outline" className="border-border">
                  Edit
                </Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

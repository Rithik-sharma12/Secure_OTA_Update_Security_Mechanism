'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Download, Plus, Eye, BarChart3, FileText, TrendingUp, Calendar } from 'lucide-react';
import { formatUtcDate } from '@/lib/formatters';
import { downloadRuntimePayload, executeRuntimeAction, fetchRuntimeActionState, type RuntimeDownloadPayload } from '@/lib/runtime-actions';

type RuntimeReportRecord = {
  id: string;
  title: string;
  type: string;
  format: 'PDF' | 'CSV' | 'JSON';
  status: 'generated' | 'generating' | 'failed';
  createdAt: string;
  sizeBytes: number;
  content: string;
};

const reportTypes = [
  { name: 'Device Health', key: 'device-health', description: 'Comprehensive device status and metrics' },
  { name: 'Deployment', key: 'deployment', description: 'Firmware update and deployment history' },
  { name: 'Security', key: 'security', description: 'Security audit and compliance report' },
  { name: 'Performance', key: 'performance', description: 'System performance analysis and trends' },
];

const scheduledReports = [
  { name: 'Monthly Health Report', schedule: 'First day of each month at 2:00 AM', next: 'Apr 1, 2024' },
  { name: 'Weekly Deployment Summary', schedule: 'Every Sunday at 6:00 PM', next: 'Mar 17, 2024' },
];

function formatBytes(bytes: number) {
  if (!bytes || bytes < 1024) {
    return `${bytes || 0} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderReportIcon(type: string) {
  if (type.includes('deployment')) {
    return <TrendingUp className="w-5 h-5 text-primary" />;
  }

  if (type.includes('security')) {
    return <FileText className="w-5 h-5 text-yellow-500" />;
  }

  return <BarChart3 className="w-5 h-5 text-accent" />;
}

export default function ReportsPage() {
  const [reports, setReports] = React.useState<RuntimeReportRecord[]>([]);
  const [selectedReportId, setSelectedReportId] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const loadReports = React.useCallback(async () => {
    try {
      const response = await fetchRuntimeActionState<{ reports?: RuntimeReportRecord[] }>();
      setReports(response.data?.reports || []);
    } catch {
      setReports([]);
    }
  }, []);

  React.useEffect(() => {
    void loadReports();
  }, [loadReports]);

  const handleGenerate = async (type: string, format: 'PDF' | 'CSV' | 'JSON' = 'PDF') => {
    setBusyAction(`generate:${type}`);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('reports.generate', {
        type,
        format,
      });
      setActionMessage(response.message || 'Report generated.');
      await loadReports();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Failed to generate report.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleDownload = async (reportId: string) => {
    setBusyAction(`download:${reportId}`);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<RuntimeDownloadPayload>('reports.download', {
        reportId,
      });

      if (response.data) {
        downloadRuntimePayload(response.data);
      }

      setActionMessage(response.message || 'Report download is ready.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to download this report.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleView = (reportId: string) => {
    setSelectedReportId(reportId);
    const selected = reports.find((report) => report.id === reportId);
    if (selected) {
      setActionError(null);
      setActionMessage(`Viewing ${selected.title}.`);
    }
  };

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
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
          onClick={() => void handleGenerate('general')}
          disabled={busyAction === 'generate:general'}
        >
          <Plus className="w-4 h-4 mr-2" />
          {busyAction === 'generate:general' ? 'Generating...' : 'Generate New Report'}
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Report Templates</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {reportTypes.map((type) => (
            <Card key={type.name} className="glass border-border/50 hover:border-primary/50 transition-all cursor-pointer group">
              <CardContent className="pt-6">
                <div className="space-y-3">
                  <p className="font-semibold text-foreground group-hover:text-primary transition-colors">{type.name}</p>
                  <p className="text-sm text-foreground/60">{type.description}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full border-border text-xs"
                    onClick={() => void handleGenerate(type.key)}
                    disabled={busyAction === `generate:${type.key}`}
                  >
                    {busyAction === `generate:${type.key}` ? 'Creating...' : 'Create'}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Generated Reports</h2>
        <div className="grid grid-cols-1 gap-4">
          {reports.length === 0 && (
            <Card className="glass border-border/50">
              <CardContent className="pt-6 text-sm text-foreground/60">
                No generated reports yet. Use one of the templates above to generate the first report.
              </CardContent>
            </Card>
          )}

          {reports.map((report) => (
            <Card
              key={report.id}
              className={`glass border-border/50 hover:border-border/80 transition-all group ${
                selectedReportId === report.id ? 'ring-1 ring-primary/40' : ''
              }`}
            >
              <CardContent className="pt-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-4 flex-1">
                    <div className="mt-1">
                      {renderReportIcon(report.type)}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors">{report.title}</h3>
                      <div className="flex items-center gap-3 mt-2 text-sm text-foreground/60 flex-wrap">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {formatUtcDate(new Date(report.createdAt))}
                        </div>
                        <Badge variant="outline" className={`text-xs ${
                          report.status === 'generated'
                            ? 'bg-chart-1/20 text-chart-1'
                            : report.status === 'failed'
                              ? 'bg-chart-4/20 text-chart-4'
                              : 'bg-chart-3/20 text-chart-3'
                        }`}>
                          {report.status}
                        </Badge>
                        <span className="text-xs">{report.format}</span>
                        <span className="text-xs text-foreground/40">{formatBytes(report.sizeBytes)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border whitespace-nowrap"
                      onClick={() => handleView(report.id)}
                    >
                      <Eye className="w-4 h-4 mr-2" />
                      View
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border whitespace-nowrap"
                      onClick={() => void handleDownload(report.id)}
                      disabled={busyAction === `download:${report.id}`}
                    >
                      <Download className="w-4 h-4 mr-2" />
                      {busyAction === `download:${report.id}` ? 'Downloading...' : 'Download'}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <Card className="glass border-border/50">
        <CardHeader>
          <CardTitle>Scheduled Reports</CardTitle>
          <CardDescription>Reports that are automatically generated on a schedule</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {scheduledReports.map((scheduled) => (
              <div key={scheduled.name} className="p-3 rounded-lg bg-muted/20 border border-border/20 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">{scheduled.name}</p>
                  <p className="text-xs text-foreground/60 mt-1">{scheduled.schedule}</p>
                  <p className="text-xs text-foreground/50 mt-1">Next: {scheduled.next}</p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-border"
                  onClick={() => void handleGenerate('scheduled', 'PDF')}
                  disabled={busyAction === 'generate:scheduled'}
                >
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

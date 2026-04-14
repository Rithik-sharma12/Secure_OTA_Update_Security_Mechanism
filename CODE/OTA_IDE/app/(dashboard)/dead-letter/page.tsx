'use client';

import React from 'react';
import { toast } from 'sonner';
import { AlertCircle, Clock, RefreshCw } from 'lucide-react';
import { apiFetch } from '@/lib/client-auth';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface WebhookEntry {
  _id: string;
  eventId: string;
  type: string;
  status: 'PENDING' | 'COMPLETED' | 'FAILED';
  error?: string;
  lastError?: string;
  failedAt?: string;
  updatedAt?: string;
}

interface WebhookApiResponse {
  ok?: boolean;
  success?: boolean;
  data?: WebhookEntry[];
  message?: string;
  error?: string;
}

interface RetryApiResponse {
  ok?: boolean;
  success?: boolean;
  message?: string;
  error?: string;
}

export default function DeadLetterQueuePage() {
  const [webhooks, setWebhooks] = React.useState<WebhookEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [retryingEventId, setRetryingEventId] = React.useState<string | null>(null);

  const fetchWebhooks = React.useCallback(async () => {
    try {
      const response = await apiFetch('/api/webhooks?status=FAILED', { cache: 'no-store' });
      const payload = (await response.json()) as WebhookApiResponse;

      if (!response.ok || (!payload.ok && !payload.success)) {
        throw new Error(payload.error || 'Failed to load webhooks.');
      }

      setWebhooks(Array.isArray(payload.data) ? payload.data : []);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Network error while fetching webhooks.';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void fetchWebhooks();
  }, [fetchWebhooks]);

  const handleRetry = async (eventId: string) => {
    setRetryingEventId(eventId);

    try {
      const response = await apiFetch(`/api/webhooks/${encodeURIComponent(eventId)}/retry`, {
        method: 'POST',
      });

      const payload = (await response.json()) as RetryApiResponse;
      if (!response.ok || (!payload.ok && !payload.success)) {
        throw new Error(payload.error || 'Retry failed.');
      }

      toast.success(payload.message || 'Webhook queued for retry.');
      await fetchWebhooks();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Network error during manual retry.';
      toast.error(message);
    } finally {
      setRetryingEventId(null);
    }
  };

  if (loading) {
    return <div className="p-12 text-center text-foreground/60 font-medium">Loading dead letter queue...</div>;
  }

  return (
    <div className="space-y-6">
      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-chart-4/20 text-chart-4">
              <AlertCircle className="w-5 h-5" />
            </div>
            <div>
              <CardTitle>Dead Letter Queue</CardTitle>
              <CardDescription>Inspect permanently failed webhook deliveries and manually retry them.</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {webhooks.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border/50 px-4 py-10 text-center text-foreground/60">
              No failed webhooks found. Queue health is good.
            </div>
          ) : (
            <div className="space-y-4">
              {webhooks.map((webhook) => (
                <div
                  key={webhook.eventId}
                  className="rounded-lg border border-border/50 bg-muted/20 p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="space-y-2 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground truncate">{webhook.type || 'unknown-event'}</span>
                      <span className="text-xs bg-chart-4/20 text-chart-4 px-2 py-0.5 rounded-full font-medium">
                        FAILED
                      </span>
                    </div>
                    <p className="text-xs text-foreground/50 font-mono break-all">Event ID: {webhook.eventId}</p>
                    <p className="text-sm text-chart-4 break-words">Reason: {webhook.error || webhook.lastError || 'Unknown error'}</p>
                    <p className="text-xs text-foreground/50 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Failed at: {new Date(webhook.failedAt || webhook.updatedAt || Date.now()).toLocaleString()}
                    </p>
                  </div>

                  <Button
                    onClick={() => void handleRetry(webhook.eventId)}
                    className="w-full sm:w-auto"
                    disabled={retryingEventId === webhook.eventId}
                  >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    {retryingEventId === webhook.eventId ? 'Retrying...' : 'Manual Retry'}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

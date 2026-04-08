import React from 'react';
import { AlertTriangle, Home, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface ErrorFallbackProps {
  error: Error;
  resetError: () => void;
  title?: string;
  description?: string;
}

export function ErrorFallback({
  error,
  resetError,
  title = 'Error Loading Content',
  description = 'We encountered an unexpected error. Please try again.',
}: ErrorFallbackProps) {
  return (
    <div className="p-6 bg-background">
      <Card className="glass border-chart-4/20 max-w-2xl">
        <CardHeader>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-6 h-6 text-chart-4" />
            <div>
              <CardTitle className="text-chart-4">{title}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="p-3 rounded-lg bg-muted/30 border border-border/20">
            <p className="text-xs text-foreground/60 mb-1">Error Details:</p>
            <p className="text-sm font-mono text-foreground/80 break-all line-clamp-3">
              {error.message}
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              onClick={resetError}
              className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Try Again
            </Button>
            <Button
              onClick={() => window.location.href = '/dashboard'}
              variant="outline"
              className="flex-1 border-border"
            >
              <Home className="w-4 h-4 mr-2" />
              Go Home
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

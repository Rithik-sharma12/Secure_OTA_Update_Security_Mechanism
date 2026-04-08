'use client';

import React, { ReactNode, ReactElement } from 'react';
import { AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: (error: Error, reset: () => void) => ReactElement;
  onError?: (error: Error, errorInfo: { componentStack: string }) => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: { componentStack: string }) {
    console.error('[v0] Error caught by boundary:', error);
    console.error('[v0] Error info:', errorInfo);
    this.props.onError?.(error, errorInfo);
  }

  resetError = () => {
    this.setState({
      hasError: false,
      error: null,
    });
  };

  render() {
    if (this.state.hasError && this.state.error) {
      return this.props.fallback ? (
        this.props.fallback(this.state.error, this.resetError)
      ) : (
        <div className="p-6 bg-background">
          <Card className="glass border-chart-4/20 max-w-2xl mx-auto">
            <CardHeader>
              <div className="flex items-center gap-3">
                <AlertCircle className="w-6 h-6 text-chart-4" />
                <div>
                  <CardTitle className="text-chart-4">Something went wrong</CardTitle>
                  <CardDescription>An unexpected error occurred in this component</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-3 rounded-lg bg-chart-4/5 border border-chart-4/20">
                <p className="text-sm font-mono text-foreground/80 break-all">
                  {this.state.error.message}
                </p>
              </div>
              <Button 
                onClick={this.resetError}
                className="bg-primary hover:bg-primary/90 text-primary-foreground"
              >
                Try Again
              </Button>
            </CardContent>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}

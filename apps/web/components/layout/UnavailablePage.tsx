import Link from 'next/link';
import { Ban } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';

/**
 * Shown on routes the console keeps but has no backend for yet. They are
 * left out of navigation; this is what a bookmarked link lands on.
 */
export function UnavailablePage({ title, reason }: { title: string; reason: string }) {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-foreground">{title}</h1>
      <Card>
        <CardContent>
          <EmptyState
            icon={<Ban className="h-5 w-5" />}
            title="This page is not available yet."
            action={
              <Button asChild variant="outline">
                <Link href="/dashboard">Back to the dashboard</Link>
              </Button>
            }
          >
            {reason}
          </EmptyState>
        </CardContent>
      </Card>
    </div>
  );
}

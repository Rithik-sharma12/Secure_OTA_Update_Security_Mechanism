'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Save, Copy, RefreshCw } from 'lucide-react';
import { mockManifest } from '@/lib/mock-data';
import { formatUtcDate } from '@/lib/formatters';

export default function ManifestPage() {
  // Create a serializable manifest object without Date objects
  const serializableManifest = {
    ...mockManifest,
    createdAt: mockManifest.createdAt instanceof Date ? mockManifest.createdAt.toISOString() : mockManifest.createdAt,
  };
  
  const manifestJson = JSON.stringify(serializableManifest, null, 2);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Manifest Editor</h1>
          <p className="text-foreground/70 mt-1">Manage firmware manifest configurations</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" className="border-border">
            <RefreshCw className="w-4 h-4 mr-2" />
            Reset
          </Button>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
            <Save className="w-4 h-4 mr-2" />
            Save
          </Button>
        </div>
      </div>

      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Release Manifest</CardTitle>
              <CardDescription>JSON configuration for v{mockManifest.entries[0]?.version}</CardDescription>
            </div>
            <Button size="sm" variant="outline" className="border-border">
              <Copy className="w-4 h-4 mr-2" />
              Copy
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted/30 rounded-lg p-4 overflow-x-auto text-sm text-foreground/80 font-mono max-h-96 overflow-y-auto">
            {manifestJson}
          </pre>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Manifest Info</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-foreground/50 mb-1">ID</p>
              <p className="text-sm font-mono text-foreground">{mockManifest.id}</p>
            </div>
            <div>
              <p className="text-xs text-foreground/50 mb-1">Entries</p>
              <p className="text-sm font-semibold text-foreground">{mockManifest.entries.length}</p>
            </div>
            <div>
              <p className="text-xs text-foreground/50 mb-1">Created</p>
              <p className="text-sm text-foreground">
                {formatUtcDate(mockManifest.createdAt)}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Signature</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-foreground/50 mb-2">RSA-2048</p>
            <p className="text-xs font-mono text-foreground/60 break-all">{mockManifest.signature}</p>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Validation</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge className="bg-chart-1/20 text-chart-1 w-full text-center justify-center">
              Valid
            </Badge>
            <p className="text-xs text-foreground/50 mt-2 text-center">All checksums verified</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

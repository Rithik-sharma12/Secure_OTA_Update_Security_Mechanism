'use client';

import React from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Download, Plus, Archive, Eye } from 'lucide-react';
import { mockReleases } from '@/lib/mock-data';
import { formatNumber, formatUtcDate } from '@/lib/formatters';

function getStatusColor(status: string) {
  switch (status) {
    case 'published':
      return 'bg-chart-1/20 text-chart-1';
    case 'draft':
      return 'bg-chart-3/20 text-chart-3';
    case 'archived':
      return 'bg-muted text-muted-foreground';
    default:
      return 'bg-muted text-muted-foreground';
  }
}

export default function ReleasesPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Releases</h1>
          <p className="text-foreground/70 mt-1">Firmware release history and management</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
          <Plus className="w-4 h-4 mr-2" />
          New Release
        </Button>
      </div>

      {/* Releases List */}
      <div className="space-y-4">
        {mockReleases.map((release) => (
          <Card key={release.id} className="glass border-border/50 hover:border-border/80 transition-colors">
            <CardContent className="pt-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-foreground">
                      v{release.version}
                    </h3>
                    <Badge
                      variant="outline"
                      className={`capitalize text-xs ${getStatusColor(release.status)}`}
                    >
                      {release.status}
                    </Badge>
                  </div>
                  <p className="text-foreground/70 mb-3">{release.description}</p>
                  
                  {/* Release Info */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Release Date</p>
                      <p className="text-sm font-medium text-foreground">
                        {formatUtcDate(release.releaseDate)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Downloads</p>
                      <p className="text-sm font-medium text-foreground">
                        {formatNumber(release.downloadCount)}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-foreground/50 mb-1">Assets</p>
                      <p className="text-sm font-medium text-foreground">
                        {release.assets.length} file(s)
                      </p>
                    </div>
                  </div>

                  {/* Compatible Devices */}
                  <div className="mb-4">
                    <p className="text-xs text-foreground/50 mb-2">Compatible Devices</p>
                    <div className="flex flex-wrap gap-2">
                      {release.compatible.map((device) => (
                        <Badge
                          key={device}
                          variant="secondary"
                          className="bg-secondary/30 text-foreground/80 text-xs"
                        >
                          {device}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Changelog */}
                  <div className="bg-muted/30 rounded-lg p-3 mb-4">
                    <p className="text-xs text-foreground/50 mb-2">Changelog</p>
                    <pre className="text-xs text-foreground/70 whitespace-pre-wrap break-words font-mono">
                      {release.changelog}
                    </pre>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex-shrink-0 ml-4 flex flex-col gap-2">
                  <Button size="sm" className="bg-primary hover:bg-primary/90 text-primary-foreground">
                    <Download className="w-4 h-4 mr-1" />
                    Download
                  </Button>
                  <Button size="sm" variant="outline" className="border-border">
                    <Eye className="w-4 h-4 mr-1" />
                    View
                  </Button>
                  {release.status === 'published' && (
                    <Button size="sm" variant="outline" className="border-border">
                      <Archive className="w-4 h-4 mr-1" />
                      Archive
                    </Button>
                  )}
                </div>
              </div>

              {/* Assets */}
              {release.assets.length > 0 && (
                <div className="border-t border-border/50 pt-4">
                  <p className="text-xs text-foreground/50 mb-3 font-semibold">Assets</p>
                  <div className="space-y-2">
                    {release.assets.map((asset) => (
                      <div key={asset.id} className="flex items-center justify-between p-2 rounded bg-muted/20 text-xs">
                        <div>
                          <p className="text-foreground font-medium">{asset.name}</p>
                          <p className="text-foreground/50">
                            {(asset.size / 1024).toFixed(2)} KB • SHA256: {asset.checksum.substring(0, 8)}...
                          </p>
                        </div>
                        <Button size="sm" variant="ghost" className="h-7">
                          <Download className="w-3 h-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Total Releases', value: mockReleases.length, color: 'bg-chart-2/20 text-chart-2' },
          { label: 'Published', value: mockReleases.filter(r => r.status === 'published').length, color: 'bg-chart-1/20 text-chart-1' },
          { label: 'Total Downloads', value: formatNumber(mockReleases.reduce((sum, r) => sum + r.downloadCount, 0)), color: 'bg-primary/20 text-primary' },
        ].map((stat) => (
          <Card key={stat.label} className="glass border-border/50">
            <CardContent className="pt-6">
              <p className="text-sm text-foreground/70 mb-1">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

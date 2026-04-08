'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tag, GitBranch, Copy, Check, Download, AlertCircle } from 'lucide-react';

export default function VersionPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <Tag className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-foreground">Version Management</h1>
          <p className="text-foreground/70 mt-1">Release versioning, tagging, and deployment history</p>
        </div>
      </div>

      {/* Current Version Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="glass border-border/50 hover:border-primary/50 transition-all md:col-span-2">
          <CardHeader>
            <CardTitle className="text-2xl">Current Version</CardTitle>
            <CardDescription>Active OTA IDE version</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-baseline gap-4">
              <div className="text-5xl font-bold text-primary">2.4.0</div>
              <Badge className="bg-chart-1/20 text-chart-1 text-base px-3 py-1">Latest</Badge>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Released</p>
                <p className="font-semibold text-foreground">March 15, 2024</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Build Hash</p>
                <p className="font-mono text-sm text-foreground">a1b2c3d4</p>
              </div>
            </div>
            <div className="p-4 rounded-lg bg-chart-1/5 border border-chart-1/20">
              <p className="text-sm text-foreground/80">
                <span className="font-semibold">New in v2.4.0:</span> Improved performance, security patches, and device compatibility enhancements.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="glass border-border/50 hover:border-border/80 transition-all">
          <CardHeader>
            <CardTitle>Git Information</CardTitle>
            <CardDescription>Repository details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Branch</p>
                <div className="flex items-center gap-2 p-2 bg-muted/20 rounded border border-border/20">
                  <GitBranch className="w-4 h-4 text-primary" />
                  <span className="text-sm font-mono text-foreground">main</span>
                </div>
              </div>
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Commit</p>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-foreground/80">abc123def456</span>
                  <Button size="sm" variant="ghost" className="h-6 w-6 p-0">
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </div>
              <div>
                <p className="text-xs text-foreground/60 uppercase tracking-wider mb-1">Author</p>
                <p className="text-sm text-foreground">DevOps Team</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Version History */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Release History</CardTitle>
          <CardDescription>Previous versions and releases</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { version: '2.4.0', date: 'Mar 15, 2024', status: 'latest', downloads: '1.2K', changes: 15 },
              { version: '2.3.1', date: 'Feb 20, 2024', status: 'stable', downloads: '847', changes: 4 },
              { version: '2.3.0', date: 'Feb 1, 2024', status: 'stable', downloads: '2.1K', changes: 12 },
              { version: '2.2.0', date: 'Jan 10, 2024', status: 'deprecated', downloads: '3.4K', changes: 8 },
            ].map((v) => (
              <div key={v.version} className="p-4 rounded-lg border border-border/50 hover:border-border/80 hover:bg-muted/20 transition-all group">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Tag className="w-4 h-4 text-muted-foreground" />
                        <p className="font-bold text-foreground">v{v.version}</p>
                        <Badge variant="outline" className={`text-xs ${
                          v.status === 'latest' ? 'bg-chart-1/20 text-chart-1' : 
                          v.status === 'stable' ? 'bg-primary/20 text-primary' :
                          'bg-muted text-muted-foreground'
                        }`}>
                          {v.status}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-foreground/50">
                        <span>{v.date}</span>
                        <span className="text-foreground/30">•</span>
                        <span>{v.changes} changes</span>
                        <span className="text-foreground/30">•</span>
                        <span>{v.downloads} downloads</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button size="sm" variant="outline" className="border-border">
                      <Download className="w-3 h-3 mr-1" />
                      Download
                    </Button>
                    <Button size="sm" variant="outline" className="border-border">
                      View Notes
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Create New Tag */}
      <Card className="glass border-border/50 hover:border-border/80 transition-all">
        <CardHeader>
          <CardTitle>Create New Release Tag</CardTitle>
          <CardDescription>Tag current commit as a new release version</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">Version Number</label>
              <input 
                placeholder="e.g., v2.5.0"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">Release Date</label>
              <input 
                type="date"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">Release Notes</label>
            <textarea 
              placeholder="Document new features, improvements, and bug fixes..."
              className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 resize-none focus:outline-none focus:border-primary/50"
              rows={4}
            />
          </div>
          <Button className="bg-primary hover:bg-primary/90 text-primary-foreground w-full">
            <Tag className="w-4 h-4 mr-2" />
            Create Release Tag
          </Button>
        </CardContent>
      </Card>

      {/* Compatibility Info */}
      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-chart-3" />
            <div>
              <CardTitle>Version Compatibility</CardTitle>
              <CardDescription>Device and firmware compatibility information</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { device: 'ESP32', compat: 'v2.0+', note: 'Fully supported' },
              { device: 'ESP8266', compat: 'v2.2+', note: 'Limited features' },
              { device: 'ATmega328P', compat: 'v1.8+', note: 'Basic support' },
              { device: 'STM32F103', compat: 'v2.3+', note: 'Full support' },
            ].map((item) => (
              <div key={item.device} className="p-3 rounded-lg bg-muted/20 border border-border/20">
                <div className="flex items-center justify-between mb-1">
                  <p className="font-medium text-foreground">{item.device}</p>
                  <Badge variant="outline" className="bg-chart-1/20 text-chart-1 text-xs">
                    {item.compat}
                  </Badge>
                </div>
                <p className="text-xs text-foreground/60">{item.note}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

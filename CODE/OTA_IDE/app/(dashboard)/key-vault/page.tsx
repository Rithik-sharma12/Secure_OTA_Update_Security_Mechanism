'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Plus, Lock } from 'lucide-react';
import { mockKeys, mockCertificates } from '@/lib/mock-data';
import { formatUtcDate } from '@/lib/formatters';

export default function KeyVaultPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Key Vault</h1>
          <p className="text-foreground/70 mt-1">Manage cryptographic keys and certificates</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90 text-primary-foreground">
          <Plus className="w-4 h-4 mr-2" />
          Add Key
        </Button>
      </div>

      {/* Keys Section */}
      <div>
        <h2 className="text-xl font-semibold text-foreground mb-4">Cryptographic Keys</h2>
        <div className="grid grid-cols-1 gap-4">
          {mockKeys.map((key) => (
            <Card key={key.id} className="glass border-border/50">
              <CardContent className="pt-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3 flex-1">
                    <Lock className="w-5 h-5 text-primary mt-1 flex-shrink-0" />
                    <div>
                      <h3 className="font-semibold text-foreground">{key.name}</h3>
                      <div className="flex items-center gap-2 mt-2">
                        <Badge variant="outline" className="bg-muted/50 text-foreground/70 text-xs">
                          {key.type}
                        </Badge>
                        <Badge variant="outline" className="bg-muted/50 text-foreground/70 text-xs">
                          {key.keySize} bit
                        </Badge>
                        {key.active && (
                          <Badge className="bg-chart-1/20 text-chart-1 text-xs">Active</Badge>
                        )}
                      </div>
                      <div className="flex gap-6 mt-3 text-xs text-foreground/60">
                        <span>Created: {formatUtcDate(key.createdAt)}</span>
                        {key.expiresAt && (
                          <span>Expires: {formatUtcDate(key.expiresAt)}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <Button size="sm" variant="outline" className="border-border">
                    View
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Certificates Section */}
      <div>
        <h2 className="text-xl font-semibold text-foreground mb-4">Certificates</h2>
        <div className="grid grid-cols-1 gap-4">
          {mockCertificates.map((cert) => (
            <Card key={cert.id} className="glass border-border/50">
              <CardContent className="pt-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="font-semibold text-foreground">{cert.name}</h3>
                    <p className="text-sm text-foreground/60 mt-1">Issued by: {cert.issuer}</p>
                    <p className="text-sm text-foreground/60">Subject: {cert.subject}</p>
                    <div className="flex gap-6 mt-3 text-xs text-foreground/60">
                      <span>Valid: {formatUtcDate(cert.validFrom)} - {formatUtcDate(cert.validTo)}</span>
                    </div>
                    <p className="text-xs text-foreground/50 mt-2 font-mono break-all">
                      Fingerprint: {cert.fingerprint}
                    </p>
                  </div>
                  <Button size="sm" variant="outline" className="border-border flex-shrink-0">
                    View
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

'use client';

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Plus, Lock } from 'lucide-react';
import { formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';
import { executeRuntimeAction, fetchRuntimeActionState } from '@/lib/runtime-actions';

type GeneratedKeyRecord = {
  id: string;
  name: string;
  type: 'RSA' | 'ECDSA' | 'AES';
  keySize: number;
  createdAt: string;
  active: boolean;
  fingerprint: string;
};

export default function KeyVaultPage() {
  const { snapshot } = useRuntimeSnapshot();
  const [generatedKeys, setGeneratedKeys] = React.useState<GeneratedKeyRecord[]>([]);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const loadGeneratedKeys = async () => {
      try {
        const response = await fetchRuntimeActionState<{ generatedKeys?: GeneratedKeyRecord[] }>();
        setGeneratedKeys(response.data?.generatedKeys || []);
      } catch {
        setGeneratedKeys([]);
      }
    };

    void loadGeneratedKeys();
  }, []);

  const keys = [
    ...generatedKeys.map((key) => ({
      ...key,
      createdAt: new Date(key.createdAt),
      expiresAt: undefined,
    })),
    ...snapshot.keys,
  ];
  const certificates = snapshot.certificates;

  const handleCreateKey = async () => {
    setBusyAction('keys.create');
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<{ key?: GeneratedKeyRecord }>('keys.create', {
        name: `Vault Key ${new Date().toISOString().slice(0, 10)}`,
        type: 'RSA',
      });

      const key = response.data?.key;
      if (key) {
        setGeneratedKeys((current) => [key, ...current].slice(0, 100));
      }

      setActionMessage(response.message || 'Cryptographic key generated.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to create key.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleInspect = async (name: string, recordId: string) => {
    setBusyAction(recordId);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('keys.inspect', {
        recordId,
        name,
      });
      setActionMessage(response.message || `Opened ${name}.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to inspect selected item.');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Key Vault</h1>
          <p className="text-foreground/70 mt-1">Manage cryptographic keys and certificates</p>
          {!snapshot.connection.reachable && snapshot.connection.error && (
            <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
          )}
        </div>
        <Button
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
          onClick={() => void handleCreateKey()}
          disabled={busyAction === 'keys.create'}
        >
          <Plus className="w-4 h-4 mr-2" />
          {busyAction === 'keys.create' ? 'Generating...' : 'Add Key'}
        </Button>
      </div>
      {actionError && <p className="text-sm text-chart-4">{actionError}</p>}
      {actionMessage && !actionError && <p className="text-sm text-chart-1">{actionMessage}</p>}

      {/* Keys Section */}
      <div>
        <h2 className="text-xl font-semibold text-foreground mb-4">Cryptographic Keys</h2>
        <div className="grid grid-cols-1 gap-4">
          {keys.map((key) => (
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
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-border"
                    onClick={() => void handleInspect(key.name, key.id)}
                    disabled={busyAction === key.id}
                  >
                    View
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
          {keys.length === 0 && (
            <Card className="glass border-border/50">
              <CardContent className="pt-6 text-sm text-foreground/60">
                No live key records detected. Connect your key service to publish runtime key metadata.
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Certificates Section */}
      <div>
        <h2 className="text-xl font-semibold text-foreground mb-4">Certificates</h2>
        <div className="grid grid-cols-1 gap-4">
          {certificates.map((cert) => (
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
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-border flex-shrink-0"
                    onClick={() => void handleInspect(cert.name, cert.id)}
                    disabled={busyAction === cert.id}
                  >
                    View
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
          {certificates.length === 0 && (
            <Card className="glass border-border/50">
              <CardContent className="pt-6 text-sm text-foreground/60">
                No live certificates detected. Runtime certificate data will appear when your PKI integration is active.
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

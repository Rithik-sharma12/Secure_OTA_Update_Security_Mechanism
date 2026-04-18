'use client';

import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Plus, Lock } from 'lucide-react';
import { formatUtcDate } from '@/lib/formatters';
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

type KeyVaultEntry = {
  id: string;
  name: string;
  type: 'RSA' | 'ECDSA' | 'AES';
  keySize: number;
  createdAt: Date;
  expiresAt?: Date;
  active: boolean;
  fingerprint?: string;
};

function getLocalDateTag(date: Date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export default function KeyVaultPage() {
  const [generatedKeys, setGeneratedKeys] = React.useState<GeneratedKeyRecord[]>([]);
  const [selectedKeyId, setSelectedKeyId] = React.useState<string | null>(null);
  const [busyAction, setBusyAction] = React.useState<string | null>(null);
  const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  const loadGeneratedKeys = React.useCallback(async () => {
    try {
      const response = await fetchRuntimeActionState<{ generatedKeys?: GeneratedKeyRecord[] }>();
      setGeneratedKeys(response.data?.generatedKeys || []);
    } catch {
      setGeneratedKeys([]);
    }
  }, []);

  React.useEffect(() => {
    void loadGeneratedKeys();
  }, [loadGeneratedKeys]);

  const keys = React.useMemo<KeyVaultEntry[]>(() => (
    generatedKeys.map((key, index) => {
      const parsedCreatedAt = new Date(key.createdAt);

      return {
        id: key.id || `runtime-key-${index + 1}`,
        name: key.name,
        type: key.type,
        keySize: key.keySize,
        createdAt: Number.isNaN(parsedCreatedAt.getTime()) ? new Date(0) : parsedCreatedAt,
        expiresAt: undefined,
        active: key.active,
        fingerprint: key.fingerprint,
      };
    })
  ), [generatedKeys]);
  const selectedKey = React.useMemo(
    () => keys.find((key) => key.id === selectedKeyId) || null,
    [keys, selectedKeyId]
  );

  React.useEffect(() => {
    if (keys.length === 0) {
      setSelectedKeyId(null);
      return;
    }

    if (!selectedKeyId || !keys.some((key) => key.id === selectedKeyId)) {
      setSelectedKeyId(keys[0].id);
    }
  }, [keys, selectedKeyId]);

  const handleCreateKey = async () => {
    setBusyAction('keys.create');
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction<{ key?: GeneratedKeyRecord }>('keys.create', {
        name: `Vault Key ${getLocalDateTag(new Date())}`,
        type: 'RSA',
      });

      const key = response.data?.key;
      if (key) {
        await loadGeneratedKeys();
        if (key.id) {
          setSelectedKeyId(key.id);
        }
      }

      setActionMessage(response.message || 'Cryptographic key generated.');
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to create key.');
    } finally {
      setBusyAction(null);
    }
  };

  const handleInspectKey = async (key: KeyVaultEntry) => {
    setSelectedKeyId(key.id);
    setBusyAction(key.id);
    setActionError(null);
    setActionMessage(null);

    try {
      const response = await executeRuntimeAction('keys.inspect', {
        recordId: key.id,
        name: key.name,
      });
      setActionMessage(response.message || `Opened ${key.name}.`);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to inspect selected key.');
    } finally {
      setBusyAction(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Key Vault</h1>
          <p className="text-foreground/70 mt-1">Manage cryptographic keys</p>
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="glass border-border/50">
          <CardContent className="pt-6">
            <p className="text-sm text-foreground/60">Total Keys</p>
            <p className="text-2xl font-semibold text-foreground">{keys.length}</p>
          </CardContent>
        </Card>
        <Card className="glass border-border/50">
          <CardContent className="pt-6">
            <p className="text-sm text-foreground/60">Active Keys</p>
            <p className="text-2xl font-semibold text-foreground">{keys.filter((key) => key.active).length}</p>
          </CardContent>
        </Card>
      </div>

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
                    onClick={() => void handleInspectKey(key)}
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
                No key records found. Use Add Key to generate the first key.
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Selected Key Details */}
      <div>
        <h2 className="text-xl font-semibold text-foreground mb-4">Selected Key Details</h2>
        <Card className="glass border-border/50">
          <CardContent className="pt-6">
            {selectedKey ? (
              <div className="space-y-2 text-sm text-foreground/80">
                <p><span className="text-foreground/60">Name:</span> {selectedKey.name}</p>
                <p><span className="text-foreground/60">Type:</span> {selectedKey.type}</p>
                <p><span className="text-foreground/60">Key Size:</span> {selectedKey.keySize} bit</p>
                <p><span className="text-foreground/60">Created:</span> {formatUtcDate(selectedKey.createdAt)}</p>
                <p><span className="text-foreground/60">Status:</span> {selectedKey.active ? 'Active' : 'Inactive'}</p>
                <p className="break-all">
                  <span className="text-foreground/60">Fingerprint:</span>{' '}
                  {selectedKey.fingerprint || 'Unavailable'}
                </p>
              </div>
            ) : (
              <p className="text-sm text-foreground/60">No key selected.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

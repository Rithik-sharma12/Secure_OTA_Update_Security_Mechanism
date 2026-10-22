'use client';

import React from 'react';
import { Copy, KeyRound, Lock } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { EmptyState, SkeletonRows } from '@/components/ui/empty-state';
import { formatUtcDate } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';

/**
 * The gateway's signing key, read-only. Every manifest the gateway serves is
 * signed with this one key, and every device verifies against its public
 * half. Keys are created by the gateway on first start; the console does not
 * mint or rotate them.
 */
export default function KeyVaultPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();
  const [copied, setCopied] = React.useState<string | null>(null);
  const { keys, certificates, signingKey } = snapshot;

  const copyPublicKey = async () => {
    if (!signingKey) return;
    try {
      await navigator.clipboard.writeText(signingKey.publicKeyPem);
      setCopied('Public key copied to clipboard.');
    } catch {
      setCopied('The browser did not allow clipboard access.');
    }
  };

  const nothing = keys.length === 0 && !signingKey;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Key Vault</h1>
        <p className="mt-1 text-foreground/70">
          The key the gateway signs firmware manifests with. Devices verify every update against its public half.
        </p>
        {!snapshot.connection.reachable && snapshot.connection.error && (
          <p className="mt-2 text-sm text-chart-4">{snapshot.connection.error}</p>
        )}
      </div>

      {isLoading && nothing ? (
        <Card>
          <CardContent>
            <SkeletonRows rows={4} columns={2} />
          </CardContent>
        </Card>
      ) : nothing ? (
        <Card>
          <CardContent>
            <EmptyState icon={<Lock className="h-5 w-5" />} title="No signing key information.">
              The gateway did not report a signing key. Check that it is running and reachable.
            </EmptyState>
          </CardContent>
        </Card>
      ) : (
        <>
          {keys.map((key) => (
            <Card key={key.id}>
              <CardHeader>
                <div className="flex flex-wrap items-center gap-2">
                  <KeyRound className="h-5 w-5 text-primary" />
                  <CardTitle>{key.name || key.id}</CardTitle>
                  <Badge variant="outline">{key.type || 'Unknown type'}</Badge>
                  {key.keySize > 0 && <Badge variant="outline">{key.keySize} bit</Badge>}
                  <Badge variant={key.active ? 'default' : 'secondary'}>{key.active ? 'Active' : 'Inactive'}</Badge>
                </div>
                <CardDescription>Key id {key.id}</CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Key file created</p>
                  <p>{key.createdAt.getTime() > 0 ? formatUtcDate(key.createdAt) : 'Not recorded'}</p>
                </div>
                <div>
                  <p className="mb-1 text-xs text-foreground/50">Expires</p>
                  <p>{key.expiresAt ? formatUtcDate(key.expiresAt) : 'Does not expire'}</p>
                </div>
              </CardContent>
            </Card>
          ))}

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <CardTitle>Public key</CardTitle>
                  <CardDescription>
                    From GET /releases/latest/public-key. Firmware pins this key to verify manifests.
                  </CardDescription>
                </div>
                {signingKey && (
                  <Button size="sm" variant="outline" onClick={() => void copyPublicKey()}>
                    <Copy className="mr-2 h-4 w-4" />
                    Copy PEM
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4 text-sm">
              {signingKey ? (
                <>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Algorithm</p>
                      <p>{signingKey.algorithm || 'Not reported'}</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Key id</p>
                      <p className="font-mono">{signingKey.keyId || 'Not reported'}</p>
                    </div>
                  </div>
                  <div>
                    <p className="mb-1 text-xs text-foreground/50">SHA-256 fingerprint of the raw public key</p>
                    <p className="break-all font-mono text-xs">{signingKey.fingerprint || 'Not reported'}</p>
                  </div>
                  {copied && <p className="text-muted-foreground">{copied}</p>}
                  <pre className="overflow-auto rounded-lg border border-border/40 bg-muted/30 p-4 font-mono text-xs">
                    {signingKey.publicKeyPem}
                  </pre>
                </>
              ) : (
                <p className="text-muted-foreground">The gateway did not return its public key.</p>
              )}
            </CardContent>
          </Card>

          {certificates.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Key records</CardTitle>
                <CardDescription>What the gateway reports about the public key it publishes.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-sm">
                {certificates.map((certificate) => (
                  <div key={certificate.id} className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Name</p>
                      <p>{certificate.name || certificate.id}</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Subject</p>
                      <p className="font-mono">{certificate.subject || 'Not reported'}</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Issuer</p>
                      <p>{certificate.issuer || 'Not reported'}</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-foreground/50">Valid</p>
                      <p>
                        From {formatUtcDate(certificate.validFrom)}
                        {certificate.validTo ? ` to ${formatUtcDate(certificate.validTo)}` : ', no end date'}
                      </p>
                    </div>
                    <div className="sm:col-span-2">
                      <p className="mb-1 text-xs text-foreground/50">Fingerprint</p>
                      <p className="break-all font-mono text-xs">{certificate.fingerprint || 'Not reported'}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

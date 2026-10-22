'use client';

import React from 'react';
import { Terminal as TerminalIcon } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Terminal } from '@/components/terminal/Terminal';
import { useCurrentUser } from '@/lib/use-current-user';

export default function TerminalPage() {
  const [terminalOpen, setTerminalOpen] = React.useState(false);
  const { can, reasonFor } = useCurrentUser();
  const mayRunCommands = can('runtime.command');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-foreground">Terminal</h1>
        <p className="mt-1 text-foreground/70">Run allowlisted commands on the machine that hosts this console.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TerminalIcon className="h-5 w-5 text-primary" />
            Host terminal
          </CardTitle>
          <CardDescription>
            Commands run on the console server, not in your browser. Only admins can use it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            onClick={() => setTerminalOpen(true)}
            disabled={!mayRunCommands}
            title={mayRunCommands ? undefined : reasonFor('runtime.command')}
          >
            <TerminalIcon className="mr-2 h-4 w-4" />
            Open terminal
          </Button>
        </CardContent>
      </Card>

      <Terminal isOpen={terminalOpen} onClose={() => setTerminalOpen(false)} />
    </div>
  );
}

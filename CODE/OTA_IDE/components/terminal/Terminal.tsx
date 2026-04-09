'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Terminal as TerminalIcon, Trash2, X } from 'lucide-react';
import { apiFetch } from '@/lib/client-auth';

interface TerminalCommand {
  id: string;
  command: string;
  output: string;
  status: 'success' | 'error' | 'pending';
  timestamp: Date;
}

export function Terminal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [commands, setCommands] = useState<TerminalCommand[]>([]);
  const [input, setInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [commands]);

  const executeCommand = async (cmd: string) => {
    if (!cmd.trim()) return;

    if (cmd.trim().toLowerCase() === 'clear') {
      clearTerminal();
      setInput('');
      return;
    }

    const newCommand: TerminalCommand = {
      id: Date.now().toString(),
      command: cmd,
      output: '',
      status: 'pending',
      timestamp: new Date(),
    };

    setCommands((prev) => [...prev, newCommand]);
    setInput('');
    setIsExecuting(true);

    try {
      const response = await apiFetch('/api/runtime/command', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ command: cmd }),
      });

      const payload = (await response.json()) as { ok?: boolean; output?: string };

      setCommands((prev) =>
        prev.map((command) =>
          command.id === newCommand.id
            ? {
                ...command,
                output: payload.output || 'Command completed with no output.',
                status: payload.ok ? 'success' : 'error',
              }
            : command
        )
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Command execution failed.';
      setCommands((prev) =>
        prev.map((command) =>
          command.id === newCommand.id
            ? {
                ...command,
                output: message,
                status: 'error',
              }
            : command
        )
      );
    } finally {
      setIsExecuting(false);
    }
  };

  const clearTerminal = () => {
    setCommands([]);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed bottom-16 right-6 w-96 h-96 z-50">
      <Card className="glass border-border/50 h-full flex flex-col rounded-lg shadow-2xl">
        <CardHeader className="pb-3 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TerminalIcon className="w-5 h-5 text-primary" />
              <div>
                <CardTitle className="text-base">Terminal</CardTitle>
                <CardDescription className="text-xs">OTA IDE Command Line</CardDescription>
              </div>
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={onClose}
              className="h-6 w-6 p-0"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        </CardHeader>

        <CardContent className="flex-1 flex flex-col overflow-hidden p-0">
          <ScrollArea className="flex-1 w-full">
            <div className="p-4 space-y-3 font-mono text-xs">
              {commands.length === 0 && (
                <div className="text-foreground/50">
                  Welcome to OTA IDE Terminal. Type 'help' for available commands.
                </div>
              )}
              {commands.map((cmd) => (
                <div key={cmd.id} className="space-y-1">
                  <div className="text-primary">
                    $ {cmd.command}
                  </div>
                  <div
                    className={`whitespace-pre-wrap text-xs leading-relaxed ${
                      cmd.status === 'error'
                        ? 'text-chart-4'
                        : cmd.status === 'success'
                          ? 'text-chart-1'
                          : 'text-foreground/60'
                    }`}
                  >
                    {cmd.output || (cmd.status === 'pending' ? '⏳ Executing...' : '')}
                  </div>
                </div>
              ))}
              <div ref={scrollRef} />
            </div>
          </ScrollArea>

          {/* Input Area */}
          <div className="border-t border-border/50 p-3 space-y-2 flex-shrink-0">
            <div className="flex gap-2">
              <span className="text-primary font-mono text-xs">$</span>
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !isExecuting) {
                    executeCommand(input);
                  }
                }}
                placeholder="Enter command..."
                className="flex-1 bg-transparent text-xs text-foreground outline-none placeholder-foreground/40"
                disabled={isExecuting}
                autoFocus
              />
            </div>
            <div className="flex gap-2 justify-end">
              <Button
                size="sm"
                variant="outline"
                className="border-border h-7"
                onClick={clearTerminal}
              >
                <Trash2 className="w-3 h-3" />
              </Button>
              <Button
                size="sm"
                className="bg-primary hover:bg-primary/90 h-7"
                onClick={() => executeCommand(input)}
                disabled={isExecuting || !input.trim()}
              >
                Execute
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

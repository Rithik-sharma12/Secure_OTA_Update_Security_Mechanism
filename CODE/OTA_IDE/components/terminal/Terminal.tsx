'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Terminal as TerminalIcon, Trash2, X } from 'lucide-react';

interface TerminalCommand {
  id: string;
  command: string;
  output: string;
  status: 'success' | 'error' | 'pending';
  timestamp: Date;
}

const FIXED_BASE_TIME = new Date('2026-04-08T12:00:00Z').getTime();
const minute = 60 * 1000;

const fixedDate = (offsetMs: number) => new Date(FIXED_BASE_TIME + offsetMs);

export function Terminal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [commands, setCommands] = useState<TerminalCommand[]>([
    {
      id: '1',
      command: 'ota-cli build --target esp32',
      output: 'Building firmware for ESP32...\nCompiling source files...\n✓ Build complete: 245.3 KB\n✓ Checksum: a1b2c3d4e5f6g7h8',
      status: 'success',
      timestamp: fixedDate(-5 * minute),
    },
  ]);
  const [input, setInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [commands]);

  const executeCommand = (cmd: string) => {
    if (!cmd.trim()) return;

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

    // Simulate command execution
    setTimeout(() => {
      const mockOutput = getMockOutput(cmd);
      setCommands((prev) =>
        prev.map((c) =>
          c.id === newCommand.id
            ? {
              ...c,
              output: mockOutput.output,
              status: mockOutput.status,
            }
            : c
        )
      );
      setIsExecuting(false);
    }, 800);
  };

  const getMockOutput = (cmd: string) => {
    const responses: Record<string, { output: string; status: 'success' | 'error' }> = {
      'help': {
        output: `Available commands:
  build          Build firmware
  compile        Compile source code
  deploy         Deploy to devices
  status         Show device status
  logs           View device logs
  config         Show configuration
  version        Display version
  clear          Clear terminal
  help           Show this help`,
        status: 'success',
      },
      'build': {
        output: 'Compiling firmware...\n✓ Source files compiled\n✓ Linking...\n✓ Build complete\nOutput: firmware.bin (312 KB)',
        status: 'success',
      },
      'status': {
        output: 'Device Status:\n✓ ESP32-Dev-01: Online (v2.4.0)\n✓ ESP8266-Test-01: Online (v2.3.1)\n✗ ATmega-Prod-01: Offline\n✓ STM32-Beta-01: Online (v2.5.0-rc1)',
        status: 'success',
      },
      'version': {
        output: 'OTA IDE v2.4.0\nBuild: a1b2c3d4e5f6\nRelease: Stable',
        status: 'success',
      },
      'clear': {
        output: '',
        status: 'success',
      },
    };

    const base = cmd.split(' ')[0].toLowerCase();
    return responses[base] || {
      output: `Command not recognized: ${cmd}\nType 'help' for available commands`,
      status: 'error',
    };
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

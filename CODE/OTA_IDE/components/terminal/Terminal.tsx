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

const STARTUP_FIGLET = String.raw`  ____  _____ ____ _   _ ____  _____    ___ _____  _      _    _   _ ____  ____    _  _____ _____
 / ___|| ____/ ___| | | |  _ \| ____|  / _ \_   _|/ \    | |  | | | |  _ \|  _ \  / \|_   _| ____|
 \___ \|  _|| |   | | | | |_) |  _|   | | | || | / _ \   | |  | | | | |_) | | | |/ _ \ | | |  _|
  ___) | |__| |___| |_| |  _ <| |___  | |_| || |/ ___ \  | |__| |_| |  __/| |_| / ___ \| | | |___
 |____/|_____\____|\___/|_| \_\_____|  \___/ |_/_/   \_\ |_____\___/|_|   |____/_/   \_\_| |_____|
`;

const EAGLE_ASCII = String.raw`            __
           /  \
      .-._/ /\ \_.-.
     /      ||      \
    /  /\   ||   /\  \
   /__/  \__||__/  \__\
        /   ||   \
       /____||____\
`;

const TERMINAL_STAMP = String.raw`Secure_OTA_update
developed by Priyankaa - Rithik - Ritesh`;

export function Terminal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [commands, setCommands] = useState<TerminalCommand[]>([]);
  const [input, setInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    setCommands([]);
    setInput('');
    setIsExecuting(false);
    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
  }, [isOpen]);

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
      <Card className="h-full flex flex-col rounded-lg shadow-2xl border border-[#5e2750] bg-[#300a24] text-[#f4e9f6]">
        <CardHeader className="pb-3 flex-shrink-0 border-b border-[#5e2750] bg-[#2b0b21]">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TerminalIcon className="w-5 h-5 text-[#e95420]" />
              <div>
                <CardTitle className="text-base">Terminal</CardTitle>
                <CardDescription className="text-xs text-[#c2a9be]">Ubuntu Secure OTA Shell</CardDescription>
              </div>
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={onClose}
              className="h-6 w-6 p-0 text-[#eab4a2] hover:bg-[#5e2750]/50 hover:text-[#ffe6db]"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        </CardHeader>

        <CardContent className="flex-1 flex flex-col overflow-hidden p-0">
          <ScrollArea className="flex-1 w-full bg-[#300a24]">
            <div className="p-4 space-y-3 font-mono text-xs">
              <div className="rounded border border-[#5e2750] bg-[#22061b] p-3 shadow-inner shadow-black/40">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1 overflow-x-auto">
                    <pre className="inline-block whitespace-pre text-[8px] leading-[1.2] text-[#f6b07c]">
                      {STARTUP_FIGLET}
                    </pre>
                    <pre className="mt-2 inline-block whitespace-pre text-[9px] leading-[1.2] text-[#8fd46c]">
                      {EAGLE_ASCII}
                    </pre>
                  </div>
                  <pre className="whitespace-pre text-right text-[9px] leading-relaxed text-[#f0cfbf]">
                    {TERMINAL_STAMP}
                  </pre>
                </div>
                <div className="mt-2 text-[10px] text-[#ccb8cf]">Boot sequence complete. Type 'help' for available commands.</div>
              </div>
              {commands.map((cmd) => (
                <div key={cmd.id} className="space-y-1">
                  <div className="text-[#e95420]">
                    secure-ota@ubuntu:~$ {cmd.command}
                  </div>
                  <div
                    className={`whitespace-pre-wrap text-xs leading-relaxed ${
                      cmd.status === 'error'
                        ? 'text-[#ff9aa6]'
                        : cmd.status === 'success'
                          ? 'text-[#9ee07f]'
                          : 'text-[#d6c9d8]'
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
          <div className="border-t border-[#5e2750] bg-[#2b0b21] p-3 space-y-2 flex-shrink-0">
            <div className="flex gap-2">
              <span className="text-[#e95420] font-mono text-xs">secure-ota@ubuntu:~$</span>
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
                className="flex-1 bg-transparent text-xs text-[#f4e9f6] outline-none placeholder-[#b89ab5]"
                disabled={isExecuting}
                autoFocus
              />
            </div>
            <div className="flex gap-2 justify-end">
              <Button
                size="sm"
                variant="outline"
                className="h-7 border-[#7a4a70] bg-transparent text-[#f4e9f6] hover:bg-[#5e2750]/40"
                onClick={clearTerminal}
              >
                <Trash2 className="w-3 h-3" />
              </Button>
              <Button
                size="sm"
                className="h-7 bg-[#e95420] text-white hover:bg-[#ff6c37]"
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

'use client';

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal as TerminalIcon, Code, Plus, Play, Save, Download } from 'lucide-react';
import { Terminal } from '@/components/terminal/Terminal';
import { CodeEditor } from '@/components/editor/CodeEditor';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatUtcDate, formatUtcDateTime } from '@/lib/formatters';

interface CodeFile {
  id: string;
  name: string;
  language: 'json' | 'c' | 'python' | 'javascript' | 'xml';
  code: string;
  createdAt: Date;
  lastModified: Date;
}

const FIXED_BASE_TIME = new Date('2026-04-08T12:00:00Z').getTime();
const minute = 60 * 1000;
const day = 24 * 60 * 60 * 1000;

const fixedDate = (offsetMs: number) => new Date(FIXED_BASE_TIME + offsetMs);

const mockCodeFiles: CodeFile[] = [
  {
    id: '1',
    name: 'firmware-config.json',
    language: 'json',
    code: `{
  "firmware_version": "2.4.0",
  "target_devices": ["esp32", "esp8266", "atmega328p"],
  "build_config": {
    "optimization": "O2",
    "debug_symbols": true,
    "warnings_as_errors": true
  },
  "deployment": {
    "rollback_on_failure": true,
    "staged_rollout": true,
    "devices_per_batch": 10
  }
}`,
  createdAt: fixedDate(-7 * day),
  lastModified: fixedDate(-5 * minute),
  },
  {
    id: '2',
    name: 'device-bootstrap.c',
    language: 'c',
    code: `#include <stdio.h>
#include <stdlib.h>
#include "ota_config.h"

int main(void) {
    // Initialize device configuration
    ota_init();
    
    // Start OTA service
    ota_start_service();
    
    // Run main loop
    while (1) {
        ota_check_updates();
        ota_process_commands();
        delay(1000);
    }
    
    return 0;
}`,
  createdAt: fixedDate(-14 * day),
  lastModified: fixedDate(-1 * day),
  },
  {
    id: '3',
    name: 'deployment-manifest.xml',
    language: 'xml',
    code: `<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <metadata>
    <version>2.4.0</version>
    <release_date>2026-04-08</release_date>
    <description>Stability improvements and bug fixes</description>
  </metadata>
  
  <targets>
    <target name="esp32">
      <binary file="firmware-esp32.bin" size="245312" />
      <checksum algorithm="sha256">a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6</checksum>
    </target>
    <target name="esp8266">
      <binary file="firmware-esp8266.bin" size="198144" />
      <checksum algorithm="sha256">q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2</checksum>
    </target>
  </targets>
</manifest>`,
    createdAt: fixedDate(-30 * day),
    lastModified: fixedDate(-15 * day),
  },
];

export default function TerminalPage() {
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<CodeFile | null>(mockCodeFiles[0]);
  const [files, setFiles] = useState<CodeFile[]>(mockCodeFiles);

  const handleSaveCode = (code: string) => {
    if (!selectedFile) return;
    
    setFiles(files.map(f => 
      f.id === selectedFile.id 
        ? { ...f, code, lastModified: new Date() }
        : f
    ));
    
    setSelectedFile(prev => 
      prev ? { ...prev, code, lastModified: new Date() } : null
    );
    
    alert('Code saved successfully');
  };

  const handleDownloadFile = () => {
    if (!selectedFile) return;
    
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(selectedFile.code));
    element.setAttribute('download', selectedFile.name);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    
    alert('File downloaded');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Terminal & Coding Environment</h1>
        <p className="text-foreground/70 mt-1">Command-line interface and code editor for OTA IDE</p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Button 
          className="bg-primary hover:bg-primary/90 justify-start"
          onClick={() => setTerminalOpen(true)}
        >
          <TerminalIcon className="w-4 h-4 mr-2" />
          Open Terminal
        </Button>
        <Button 
          className="bg-primary hover:bg-primary/90 justify-start"
          onClick={() => setEditorOpen(true)}
        >
          <Code className="w-4 h-4 mr-2" />
          Open Editor
        </Button>
        <Button 
          variant="outline"
          className="border-border justify-start"
          onClick={handleDownloadFile}
          disabled={!selectedFile}
        >
          <Download className="w-4 h-4 mr-2" />
          Download
        </Button>
        <Button 
          variant="outline"
          className="border-border justify-start"
        >
          <Plus className="w-4 h-4 mr-2" />
          New File
        </Button>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="editor" className="w-full">
        <TabsList className="grid w-full grid-cols-2 bg-background border border-border/50">
          <TabsTrigger value="editor" className="gap-2">
            <Code className="w-4 h-4" />
            Code Editor
          </TabsTrigger>
          <TabsTrigger value="files" className="gap-2">
            <TerminalIcon className="w-4 h-4" />
            Project Files
          </TabsTrigger>
        </TabsList>

        {/* Editor Tab */}
        <TabsContent value="editor">
          <Card className="glass border-border/50">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>{selectedFile?.name}</CardTitle>
                  <CardDescription className="flex items-center gap-2 mt-1">
                    <Badge className="bg-green-500/20 text-green-400">
                      {selectedFile?.language.toUpperCase()}
                    </Badge>
                    Last modified: {selectedFile ? formatUtcDateTime(selectedFile.lastModified) : '-'}
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    className="border-border"
                    onClick={() => setEditorOpen(true)}
                  >
                    <Code className="w-4 h-4 mr-2" />
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    className="bg-primary hover:bg-primary/90"
                    onClick={handleDownloadFile}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Download
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="bg-background/50 rounded-lg overflow-hidden border border-border/50">
                <div className="flex">
                  {/* Line Numbers */}
                  <div className="bg-muted/30 border-r border-border/50 px-4 py-4 text-right font-mono text-xs text-foreground/40 select-none max-h-96 overflow-y-auto">
                    {Array.from({ length: selectedFile?.code.split('\n').length || 0 }).map((_, i) => (
                      <div key={i + 1}>{i + 1}</div>
                    ))}
                  </div>

                  {/* Code Display */}
                  <div className="flex-1 p-4 max-h-96 overflow-auto">
                    <pre className="font-mono text-sm text-foreground/80 whitespace-pre-wrap break-words">
                      {selectedFile?.code}
                    </pre>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Files Tab */}
        <TabsContent value="files">
          <Card className="glass border-border/50">
            <CardHeader>
              <CardTitle>Project Files</CardTitle>
              <CardDescription>Code files and configurations</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-2 pr-4">
                  {files.map((file) => (
                    <div
                      key={file.id}
                      onClick={() => setSelectedFile(file)}
                      className={`p-4 rounded-lg border transition-colors cursor-pointer ${
                        selectedFile?.id === file.id
                          ? 'bg-primary/20 border-primary/50'
                          : 'bg-background/50 border-border/30 hover:border-border/50'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <Code className="w-4 h-4 text-primary" />
                            <p className="font-medium text-foreground">{file.name}</p>
                          </div>
                          <p className="text-xs text-foreground/50 mt-1">
                            Created: {formatUtcDate(file.createdAt)} • {file.code.split('\n').length} lines
                          </p>
                        </div>
                        <Badge className="bg-blue-500/20 text-blue-400">
                          {file.language.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="glass border-border/50">
          <CardHeader>
            <TerminalIcon className="w-6 h-6 text-primary mb-2" />
            <CardTitle>Terminal Access</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-foreground/70">
              Execute OTA CLI commands directly. Build firmware, deploy to devices, and manage configurations from the integrated terminal.
            </p>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <Code className="w-6 h-6 text-primary mb-2" />
            <CardTitle>Code Editor</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-foreground/70">
              Edit configuration files, manifests, and source code with syntax highlighting and line numbering.
            </p>
          </CardContent>
        </Card>

        <Card className="glass border-border/50">
          <CardHeader>
            <Play className="w-6 h-6 text-primary mb-2" />
            <CardTitle>Quick Build</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-foreground/70">
              Compile firmware directly from the editor, view build output, and download compiled binaries.
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Terminal Component */}
      <Terminal isOpen={terminalOpen} onClose={() => setTerminalOpen(false)} />

      {/* Code Editor Modal */}
      <CodeEditor
        isOpen={editorOpen}
        onClose={() => setEditorOpen(false)}
        title="Edit Code"
        fileName={selectedFile?.name || 'file.txt'}
        language={selectedFile?.language || 'javascript'}
        initialCode={selectedFile?.code || ''}
        onSave={handleSaveCode}
      />
    </div>
  );
}

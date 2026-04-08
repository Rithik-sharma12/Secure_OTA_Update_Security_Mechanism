'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Code, 
  Plus, 
  Trash2, 
  Save, 
  Download, 
  Edit2, 
  X, 
  FileText, 
  Copy,
  RefreshCw,
  Eye,
  Terminal as TerminalIcon
} from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Terminal } from '@/components/terminal/Terminal';
import { formatUtcDateTime } from '@/lib/formatters';

interface CodeFile {
  id: string;
  name: string;
  language: 'json' | 'c' | 'python' | 'javascript' | 'xml' | 'cpp' | 'h';
  code: string;
  createdAt: Date;
  lastModified: Date;
}

const FIXED_BASE_TIME = new Date('2026-04-08T12:00:00Z').getTime();
const minute = 60 * 1000;
const day = 24 * 60 * 60 * 1000;

const fixedDate = (offsetMs: number) => new Date(FIXED_BASE_TIME + offsetMs);

const initialFiles: CodeFile[] = [
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
  </targets>
</manifest>`,
    createdAt: fixedDate(-30 * day),
    lastModified: fixedDate(-15 * day),
  },
];

export default function CodePage() {
  const [files, setFiles] = useState<CodeFile[]>(initialFiles);
  const [selectedFile, setSelectedFile] = useState<CodeFile | null>(initialFiles[0]);
  const [editingCode, setEditingCode] = useState(initialFiles[0].code);
  const [isEditing, setIsEditing] = useState(false);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [showNewFile, setShowNewFile] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null);
  const [showRenameDialog, setShowRenameDialog] = useState<string | null>(null);
  const [newFileName, setNewFileName] = useState('');
  const [newFileLanguage, setNewFileLanguage] = useState<CodeFile['language']>('json');
  const codeInputRef = useRef<HTMLTextAreaElement>(null);

  const handleSelectFile = (file: CodeFile) => {
    if (isEditing) {
      const confirmed = confirm('You have unsaved changes. Discard them?');
      if (!confirmed) return;
    }
    setSelectedFile(file);
    setEditingCode(file.code);
    setIsEditing(false);
  };

  const handleSaveCode = () => {
    if (!selectedFile) return;
    
    setFiles(files.map(f =>
      f.id === selectedFile.id
        ? { ...f, code: editingCode, lastModified: new Date() }
        : f
    ));
    
    setSelectedFile(prev =>
      prev ? { ...prev, code: editingCode, lastModified: new Date() } : null
    );
    
    setIsEditing(false);
    alert('File saved successfully');
  };

  const handleCreateFile = () => {
    if (!newFileName.trim()) {
      alert('Please enter a file name');
      return;
    }

    const newFile: CodeFile = {
      id: Date.now().toString(),
      name: newFileName.includes('.') ? newFileName : `${newFileName}.${getExtension(newFileLanguage)}`,
      language: newFileLanguage,
      code: '',
      createdAt: new Date(),
      lastModified: new Date(),
    };

    setFiles([...files, newFile]);
    setSelectedFile(newFile);
    setEditingCode('');
    setIsEditing(true);
    setShowNewFile(false);
    setNewFileName('');
  };

  const handleDeleteFile = (fileId: string) => {
    const updatedFiles = files.filter(f => f.id !== fileId);
    setFiles(updatedFiles);
    
    if (selectedFile?.id === fileId) {
      setSelectedFile(updatedFiles[0] || null);
      setEditingCode(updatedFiles[0]?.code || '');
    }
    
    setShowDeleteConfirm(null);
    alert('File deleted successfully');
  };

  const handleRenameFile = (fileId: string, newName: string) => {
    if (!newName.trim()) {
      alert('Please enter a file name');
      return;
    }

    setFiles(files.map(f =>
      f.id === fileId
        ? { ...f, name: newName }
        : f
    ));

    if (selectedFile?.id === fileId) {
      setSelectedFile(prev => prev ? { ...prev, name: newName } : null);
    }

    setShowRenameDialog(null);
    setNewFileName('');
    alert('File renamed successfully');
  };

  const handleDownloadFile = () => {
    if (!selectedFile) return;

    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(editingCode || selectedFile.code));
    element.setAttribute('download', selectedFile.name);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(editingCode || selectedFile?.code || '');
    alert('Code copied to clipboard');
  };

  const getExtension = (lang: CodeFile['language']) => {
    const extensions: Record<CodeFile['language'], string> = {
      json: 'json',
      c: 'c',
      cpp: 'cpp',
      h: 'h',
      python: 'py',
      javascript: 'js',
      xml: 'xml',
    };
    return extensions[lang];
  };

  const getLanguageBadgeColor = (lang: CodeFile['language']) => {
    const colors: Record<CodeFile['language'], string> = {
      json: 'bg-yellow-500/20 text-yellow-400',
      c: 'bg-blue-500/20 text-blue-400',
      cpp: 'bg-blue-600/20 text-blue-300',
      h: 'bg-blue-500/20 text-blue-400',
      python: 'bg-green-500/20 text-green-400',
      javascript: 'bg-orange-500/20 text-orange-400',
      xml: 'bg-purple-500/20 text-purple-400',
    };
    return colors[lang];
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-3 rounded-lg bg-primary/20 text-primary">
          <Code className="w-6 h-6" />
        </div>
        <div className="flex-1">
          <h1 className="text-3xl font-bold text-foreground">Code Editor</h1>
          <p className="text-foreground/70 mt-1">VSCode-like editor with full CRUD operations for firmware development</p>
        </div>
      </div>

      {/* Main Editor Area */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 min-h-96">
        {/* File Explorer Sidebar */}
        <Card className="glass border-border/50 lg:col-span-1 flex flex-col">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Code</CardTitle>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-primary hover:bg-primary/20"
                onClick={() => setShowNewFile(true)}
              >
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            <CardDescription className="text-xs">Project files ({files.length})</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 p-0">
            <ScrollArea className="h-96">
              <div className="space-y-1 px-4 py-2">
                {files.map((file) => (
                  <div
                    key={file.id}
                    className={`group relative px-3 py-2 rounded-md cursor-pointer transition-colors ${
                      selectedFile?.id === file.id
                        ? 'bg-primary/20 border-l-2 border-primary'
                        : 'hover:bg-muted/50'
                    }`}
                    onClick={() => handleSelectFile(file)}
                  >
                    <div className="flex items-center justify-between gap-2 min-w-0">
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <FileText className="w-4 h-4 flex-shrink-0 text-primary" />
                        <span className="text-sm text-foreground truncate">{file.name}</span>
                        {isEditing && selectedFile?.id === file.id && (
                          <span className="text-xs text-yellow-500 flex-shrink-0">●</span>
                        )}
                      </div>
                      <div className="hidden group-hover:flex gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-6 w-6 p-0 text-foreground/60 hover:text-foreground"
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowRenameDialog(file.id);
                            setNewFileName(file.name);
                          }}
                        >
                          <Edit2 className="w-3 h-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-6 w-6 p-0 text-chart-4 hover:text-chart-4/80"
                          onClick={(e) => {
                            e.stopPropagation();
                            setShowDeleteConfirm(file.id);
                          }}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>

                    {/* Rename Dialog */}
                    {showRenameDialog === file.id && (
                      <div className="absolute top-0 left-0 right-0 bottom-0 z-50 bg-muted/80 backdrop-blur-sm rounded-md flex items-center p-2">
                        <input
                          autoFocus
                          type="text"
                          value={newFileName}
                          onChange={(e) => setNewFileName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') handleRenameFile(file.id, newFileName);
                            if (e.key === 'Escape') setShowRenameDialog(null);
                          }}
                          className="flex-1 px-2 py-1 bg-background border border-border/50 rounded text-xs text-foreground focus:outline-none focus:border-primary"
                        />
                      </div>
                    )}

                    {/* Delete Confirmation */}
                    {showDeleteConfirm === file.id && (
                      <div className="absolute top-0 left-0 right-0 bottom-0 z-50 bg-chart-4/20 backdrop-blur-sm rounded-md flex items-center justify-between p-2 gap-1">
                        <span className="text-xs text-chart-4">Delete?</span>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            className="h-6 px-2 text-xs bg-chart-4 hover:bg-chart-4/80"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteFile(file.id);
                            }}
                          >
                            Yes
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 px-2 text-xs border-chart-4/50"
                            onClick={(e) => {
                              e.stopPropagation();
                              setShowDeleteConfirm(null);
                            }}
                          >
                            No
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Code Editor */}
        <Card className="glass border-border/50 lg:col-span-3 flex flex-col">
          {selectedFile ? (
            <>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {selectedFile.name}
                        {isEditing && <span className="text-xs text-yellow-500">• Unsaved</span>}
                      </CardTitle>
                      <CardDescription className="flex items-center gap-2 mt-1">
                        <Badge className={getLanguageBadgeColor(selectedFile.language)}>
                          {selectedFile.language.toUpperCase()}
                        </Badge>
                        <span className="text-xs">
                          {selectedFile.code.split('\n').length} lines • {formatUtcDateTime(selectedFile.lastModified)}
                        </span>
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex gap-2 flex-wrap">
                    {isEditing && (
                      <>
                        <Button
                          size="sm"
                          className="bg-primary hover:bg-primary/90"
                          onClick={handleSaveCode}
                        >
                          <Save className="w-4 h-4 mr-1" />
                          Save
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-border"
                          onClick={() => {
                            setEditingCode(selectedFile.code);
                            setIsEditing(false);
                          }}
                        >
                          <X className="w-4 h-4 mr-1" />
                          Cancel
                        </Button>
                      </>
                    )}
                    {!isEditing && (
                      <>
                        <Button
                          size="sm"
                          className="bg-primary hover:bg-primary/90"
                          onClick={() => setIsEditing(true)}
                        >
                          <Edit2 className="w-4 h-4 mr-1" />
                          Edit
                        </Button>
                      </>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={handleCopyCode}
                    >
                      <Copy className="w-4 h-4 mr-1" />
                      Copy
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-border"
                      onClick={handleDownloadFile}
                    >
                      <Download className="w-4 h-4 mr-1" />
                      Download
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="flex-1 p-0 overflow-hidden">
                <div className="h-full flex flex-col">
                  <div className="flex-1 overflow-hidden">
                    {isEditing ? (
                      <div className="flex h-full">
                        {/* Line Numbers */}
                        <div className="bg-muted/20 border-r border-border/50 px-2 py-4 text-right font-mono text-xs text-foreground/40 select-none overflow-hidden">
                          {editingCode.split('\n').map((_, i) => (
                            <div key={i}>{i + 1}</div>
                          ))}
                        </div>
                        {/* Editor */}
                        <textarea
                          ref={codeInputRef}
                          value={editingCode}
                          onChange={(e) => setEditingCode(e.target.value)}
                          className="flex-1 p-4 bg-background/50 text-sm font-mono text-foreground resize-none focus:outline-none border-none"
                          spellCheck="false"
                        />
                      </div>
                    ) : (
                      <div className="flex h-full overflow-auto">
                        {/* Line Numbers */}
                        <div className="bg-muted/20 border-r border-border/50 px-2 py-4 text-right font-mono text-xs text-foreground/40 select-none min-w-fit">
                          {selectedFile.code.split('\n').map((_, i) => (
                            <div key={i}>{i + 1}</div>
                          ))}
                        </div>
                        {/* Code Display */}
                        <pre className="flex-1 p-4 font-mono text-sm text-foreground/80 whitespace-pre-wrap break-words overflow-auto">
                          {selectedFile.code}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </>
          ) : (
            <CardContent className="flex items-center justify-center h-96 text-foreground/50">
              <div className="text-center">
                <FileText className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No file selected</p>
              </div>
            </CardContent>
          )}
        </Card>
      </div>

      {/* New File Dialog */}
      {showNewFile && (
        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle>Create New File</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">File Name</label>
              <input
                type="text"
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                placeholder="firmware.json"
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">Language</label>
              <select
                value={newFileLanguage}
                onChange={(e) => setNewFileLanguage(e.target.value as CodeFile['language'])}
                className="w-full px-3 py-2 bg-muted/50 border border-border/50 rounded-lg text-sm text-foreground focus:outline-none focus:border-primary/50"
              >
                <option value="json">JSON</option>
                <option value="c">C</option>
                <option value="cpp">C++</option>
                <option value="h">Header</option>
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
                <option value="xml">XML</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Button className="flex-1 bg-primary hover:bg-primary/90" onClick={handleCreateFile}>
                Create
              </Button>
              <Button
                variant="outline"
                className="flex-1 border-border"
                onClick={() => {
                  setShowNewFile(false);
                  setNewFileName('');
                }}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Terminal Section */}
      <Card className="glass border-border/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TerminalIcon className="w-5 h-5 text-primary" />
              <CardTitle>Terminal</CardTitle>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="border-border"
              onClick={() => setTerminalOpen(!terminalOpen)}
            >
              {terminalOpen ? <X className="w-4 h-4" /> : <TerminalIcon className="w-4 h-4" />}
            </Button>
          </div>
        </CardHeader>
        {terminalOpen && (
          <CardContent>
            <Terminal />
          </CardContent>
        )}
      </Card>
    </div>
  );
}

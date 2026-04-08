'use client';

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Copy, Save, X, Eye, Code } from 'lucide-react';

interface CodeEditorProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  fileName?: string;
  language?: 'json' | 'c' | 'python' | 'javascript' | 'xml';
  initialCode?: string;
  onSave?: (code: string) => void;
  readOnly?: boolean;
}

export function CodeEditor({
  isOpen,
  onClose,
  title = 'Code Editor',
  fileName = 'file.txt',
  language = 'javascript',
  initialCode = '',
  onSave,
  readOnly = false,
}: CodeEditorProps) {
  const [code, setCode] = useState(initialCode);
  const [preview, setPreview] = useState(false);
  const [lines, setLines] = useState(initialCode.split('\n').length);

  const handleSave = () => {
    onSave?.(code);
    alert('Code saved successfully');
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    alert('Code copied to clipboard');
  };

  const getLanguageColor = () => {
    const colors: Record<string, string> = {
      json: 'bg-yellow-500/20 text-yellow-400',
      c: 'bg-blue-500/20 text-blue-400',
      python: 'bg-purple-500/20 text-purple-400',
      javascript: 'bg-green-500/20 text-green-400',
      xml: 'bg-orange-500/20 text-orange-400',
    };
    return colors[language] || 'bg-gray-500/20 text-gray-400';
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4">
      <Card className="glass border-border/50 w-full h-5/6 max-w-4xl flex flex-col">
        <CardHeader className="pb-3 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Code className="w-5 h-5 text-primary" />
              <div>
                <CardTitle>{title}</CardTitle>
                <CardDescription className="flex items-center gap-2 mt-1">
                  {fileName}
                  <Badge className={getLanguageColor()}>{language.toUpperCase()}</Badge>
                </CardDescription>
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
          {preview ? (
            <div className="flex-1 p-6 overflow-auto bg-muted/20 space-y-4">
              <div className="prose prose-invert dark max-w-none">
                {language === 'json' ? (
                  <pre className="bg-muted/50 p-4 rounded-lg overflow-auto text-sm text-foreground/80 font-mono">
                    <code>{code}</code>
                  </pre>
                ) : (
                  <pre className="bg-muted/50 p-4 rounded-lg overflow-auto text-sm text-foreground/80 font-mono">
                    <code>{code}</code>
                  </pre>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex overflow-hidden">
              {/* Line Numbers */}
              <div className="bg-muted/30 border-r border-border/50 px-3 py-4 text-right font-mono text-xs text-foreground/40 select-none overflow-y-auto">
                {Array.from({ length: lines }).map((_, i) => (
                  <div key={i + 1}>{i + 1}</div>
                ))}
              </div>

              {/* Editor */}
              <textarea
                value={code}
                onChange={(e) => {
                  setCode(e.target.value);
                  setLines(e.target.value.split('\n').length);
                }}
                className="flex-1 bg-background p-4 font-mono text-sm text-foreground outline-none resize-none"
                spellCheck="false"
                style={{
                  backgroundColor: 'rgba(15, 10, 18, 0.8)',
                  lineHeight: '1.5',
                }}
                readOnly={readOnly}
              />
            </div>
          )}

          {/* Footer */}
          <div className="border-t border-border/50 px-4 py-3 flex items-center justify-between flex-shrink-0">
            <div className="flex items-center gap-2 text-xs text-foreground/50">
              <span>{code.length} characters</span>
              <span>•</span>
              <span>{lines} lines</span>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                className="border-border"
                onClick={() => setPreview(!preview)}
              >
                <Eye className="w-3 h-3" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-border"
                onClick={handleCopy}
              >
                <Copy className="w-3 h-3" />
              </Button>
              {!readOnly && (
                <Button
                  size="sm"
                  className="bg-primary hover:bg-primary/90"
                  onClick={handleSave}
                >
                  <Save className="w-3 h-3" />
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

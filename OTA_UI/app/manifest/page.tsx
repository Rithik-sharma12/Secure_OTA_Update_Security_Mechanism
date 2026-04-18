'use client'

import { useState } from 'react'
import { useManifest } from '@/lib/data-hooks'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { CheckCircle2, AlertCircle, Copy, Download, Eye } from 'lucide-react'

export default function ManifestPage() {
  const manifest = useManifest()
  const [copied, setCopied] = useState(false)

  const manifestJson = JSON.stringify(manifest, null, 2)

  const handleCopy = () => {
    navigator.clipboard.writeText(manifestJson)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Validation checks
  const validations = [
    {
      name: 'Version Format',
      passed: /^\d{4}\.\d{2}\.\d{2}$/.test(manifest.version),
      message: 'Version must be in YYYY.MM.DD format',
    },
    {
      name: 'Signature Present',
      passed: manifest.signature && manifest.signature.length > 0,
      message: 'Ed25519 signature must be present',
    },
    {
      name: 'All Architectures',
      passed: Object.keys(manifest.architectures).length === 4,
      message: 'All 4 architectures must have firmware',
    },
    {
      name: 'Checksum Validity',
      passed: Object.values(manifest.architectures).every((arch: any) => arch.checksum && arch.checksum.length > 0),
      message: 'All architectures must have checksums',
    },
    {
      name: 'Rollout Strategy',
      passed: manifest.rolloutStrategy && manifest.rolloutStrategy.length > 0,
      message: 'Rollout strategy must be defined',
    },
  ]
  const passedValidations = validations.filter(v => v.passed).length
  const allValidationsPassed = passedValidations === validations.length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Release Manifest</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Configure and validate the deployment manifest for version {manifest.version}
        </p>
      </div>

      {/* Validation Status */}
      <Card className="p-6 border-l-4 border-green-500 bg-green-50/50 dark:bg-green-950/20">
        <div className="flex items-start gap-4">
          <CheckCircle2 className="w-6 h-6 text-green-500 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <h3 className="font-semibold text-green-900 dark:text-green-100 mb-2">
              {allValidationsPassed ? 'Manifest Validation Passed' : 'Manifest Validation Incomplete'}
            </h3>
            <p className="text-sm text-green-800 dark:text-green-200">
              {passedValidations}/{validations.length} validation checks passed.
            </p>
          </div>
        </div>
      </Card>

      {/* Validation Details */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Validation Checks</h2>
        <div className="space-y-3">
          {validations.map((validation) => (
            <div key={validation.name} className="flex items-start gap-3 p-3 rounded-lg border border-slate-200 dark:border-slate-700">
              {validation.passed ? (
                <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              )}
              <div className="flex-1">
                <p className={`font-medium ${validation.passed ? 'text-slate-900 dark:text-white' : 'text-red-700 dark:text-red-300'}`}>
                  {validation.name}
                </p>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  {validation.message}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Manifest Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Version</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-white font-mono">{manifest.version}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Build Date</p>
          <p className="text-lg font-medium text-slate-900 dark:text-white font-mono">
            {new Date(manifest.buildDate).toLocaleDateString()}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Rollout Strategy</p>
          <p className="text-lg font-medium text-slate-900 dark:text-white capitalize">{manifest.rolloutStrategy}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Min. Device Health</p>
          <p className="text-lg font-medium text-slate-900 dark:text-white">{manifest.minimumDeviceHealth}%</p>
        </Card>
      </div>

      {/* Architecture Details */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Architecture Specifications</h2>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className="text-left px-4 py-3 font-semibold text-slate-900 dark:text-white">Architecture</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-900 dark:text-white">Filename</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-900 dark:text-white">Size</th>
                <th className="text-left px-4 py-3 font-semibold text-slate-900 dark:text-white">Checksum</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(manifest.architectures).map(([arch, details]: [string, any]) => (
                <tr key={arch} className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/50">
                  <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">{arch}</td>
                  <td className="px-4 py-3 text-sm font-mono text-slate-600 dark:text-slate-400">{details.filename}</td>
                  <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">{(details.size / 1024).toFixed(1)} KB</td>
                  <td className="px-4 py-3 text-sm font-mono text-slate-600 dark:text-slate-400">
                    {details.checksum.substring(0, 16)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Rollout Stages */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Rollout Stages</h2>
        <div className="space-y-3">
          {manifest.rolloutStages.map((stage, index) => (
            <div key={index} className="flex items-center justify-between p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
              <div>
                <p className="font-medium text-slate-900 dark:text-white">Stage {index + 1}</p>
                <p className="text-sm text-slate-600 dark:text-slate-400">
                  Roll out to {stage.percentage}% of devices
                </p>
              </div>
              <div className="text-right">
                <p className="font-mono text-sm text-slate-600 dark:text-slate-400">{stage.duration}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">Duration</p>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* JSON Editor */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Manifest JSON</h2>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleCopy}>
              <Copy className="w-4 h-4 mr-2" />
              {copied ? 'Copied!' : 'Copy'}
            </Button>
            <Button size="sm">
              <Download className="w-4 h-4 mr-2" />
              Download
            </Button>
          </div>
        </div>
        <div className="bg-slate-900 dark:bg-slate-950 rounded-lg p-4 overflow-x-auto max-h-96 overflow-y-auto">
          <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap break-words">
            {manifestJson}
          </pre>
        </div>
      </Card>
    </div>
  )
}

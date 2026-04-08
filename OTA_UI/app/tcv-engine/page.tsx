'use client'

import { useState } from 'react'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { CheckCircle2, AlertCircle, Shield } from 'lucide-react'

export default function TCVEnginePage() {
  const [simulationActive, setSimulationActive] = useState(false)

  // TCV Pipeline stages
  const stages = [
    {
      name: 'Signature Verification',
      description: 'Verify Ed25519 signature against public key',
      icon: Shield,
      passed: true,
      details: 'Signature: ed25519_sig_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\nPublic Key: pk_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k\nVerification: ✓ PASSED',
    },
    {
      name: 'Checksum Validation',
      description: 'Validate firmware integrity with SHA256',
      icon: Shield,
      passed: true,
      details: 'Expected: sha256_abc123def456789...\nComputed: sha256_abc123def456789...\nMatch: ✓ PASSED',
    },
    {
      name: 'Version Compatibility',
      description: 'Check version gate and upgrade path',
      icon: Shield,
      passed: true,
      details: 'Current: v1.2.3\nTarget: v2024.02.15\nPath Valid: ✓ PASSED',
    },
    {
      name: 'Manifest Validation',
      description: 'Verify manifest structure and content',
      icon: Shield,
      passed: true,
      details: 'Architecture: ATmega328P\nFile: firmware-atmega.bin\nSize: 32256 bytes\nValidation: ✓ PASSED',
    },
    {
      name: 'Security Policy Check',
      description: 'Enforce security policies and restrictions',
      icon: Shield,
      passed: true,
      details: 'Min Health: 40 (Device: 78)\nTrusted Publisher: ✓ Yes\nRollout Approved: ✓ Yes',
    },
  ]

  const passedCount = stages.filter(s => s.passed).length
  const passRate = Math.round((passedCount / stages.length) * 100)

  // Mock attack simulation data
  const attackScenarios = [
    { name: 'Invalid Signature', blocked: true },
    { name: 'Corrupted Checksum', blocked: true },
    { name: 'Downgrade Attack', blocked: true },
    { name: 'Man-in-the-Middle', blocked: true },
    { name: 'Malicious Manifest', blocked: true },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">TCV Engine</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Trust Chain Verification and Security Validation System
        </p>
      </div>

      {/* Overall Pass Rate */}
      <Card className="p-6 border-l-4 border-teal-500 bg-teal-50/50 dark:bg-teal-950/20">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-4 flex-1">
            <CheckCircle2 className="w-6 h-6 text-teal-500 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-teal-900 dark:text-teal-100 mb-1">All Verification Stages Passed</h3>
              <p className="text-sm text-teal-800 dark:text-teal-200">
                {passedCount}/{stages.length} security checks completed successfully
              </p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-3xl font-bold text-teal-600 dark:text-teal-400">{passRate}%</p>
            <p className="text-xs text-teal-700 dark:text-teal-300 font-medium">Pass Rate</p>
          </div>
        </div>
      </Card>

      {/* TCV Pipeline Visualization */}
      <div className="space-y-3">
        {stages.map((stage, index) => {
          const IconComponent = stage.icon
          return (
            <div key={stage.name}>
              <Card className={`p-6 border-l-4 transition-all ${stage.passed ? 'border-green-500 bg-green-50/50 dark:bg-green-950/20' : 'border-red-500 bg-red-50/50 dark:bg-red-950/20'}`}>
                <div className="space-y-4">
                  {/* Stage Header */}
                  <div className="flex items-start gap-4">
                    <div className={`p-2 rounded-lg ${stage.passed ? 'bg-green-100 dark:bg-green-950' : 'bg-red-100 dark:bg-red-950'}`}>
                      {stage.passed ? (
                        <CheckCircle2 className="w-5 h-5 text-green-600 dark:text-green-400" />
                      ) : (
                        <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                          Stage {index + 1}: {stage.name}
                        </h3>
                        <span className={`px-2 py-1 rounded text-xs font-bold ${stage.passed ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300' : 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300'}`}>
                          {stage.passed ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>
                      <p className="text-sm text-slate-600 dark:text-slate-400">
                        {stage.description}
                      </p>
                    </div>
                  </div>

                  {/* Details */}
                  <div className="bg-slate-900 dark:bg-slate-950 rounded font-mono text-xs text-slate-300 p-3 max-h-32 overflow-y-auto">
                    <pre className="whitespace-pre-wrap break-words">{stage.details}</pre>
                  </div>
                </div>
              </Card>

              {/* Connector */}
              {index < stages.length - 1 && (
                <div className="flex justify-center py-2">
                  <div className="w-0.5 h-6 bg-slate-300 dark:bg-slate-700" />
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Attack Mitigation */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Attack Mitigation</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
          The TCV Engine blocks the following known attack vectors:
        </p>
        <div className="space-y-2">
          {attackScenarios.map((attack) => (
            <div key={attack.name} className="flex items-center gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
              {attack.blocked ? (
                <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
              )}
              <span className="text-sm font-medium text-slate-900 dark:text-white">{attack.name}</span>
              <span className={`ml-auto px-2 py-1 rounded text-xs font-bold ${attack.blocked ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300' : 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300'}`}>
                {attack.blocked ? 'BLOCKED' : 'ALLOWED'}
              </span>
            </div>
          ))}
        </div>
      </Card>

      {/* Simulation Controls */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Simulation &amp; Testing</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
          Test the TCV Engine with various attack scenarios and verification conditions.
        </p>
        <div className="flex gap-2">
          <Button
            variant={simulationActive ? 'default' : 'outline'}
            onClick={() => setSimulationActive(!simulationActive)}
          >
            {simulationActive ? 'Stop Simulation' : 'Run Simulation'}
          </Button>
          <Button variant="outline">Test Invalid Signature</Button>
          <Button variant="outline">Test Corrupted Checksum</Button>
          <Button variant="outline">Test Downgrade Attack</Button>
        </div>
        {simulationActive && (
          <div className="mt-4 p-4 rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900">
            <p className="text-sm text-blue-900 dark:text-blue-100">
              <span className="inline-block w-2 h-2 bg-blue-500 rounded-full animate-pulse mr-2" />
              Simulation running... Injecting test vectors
            </p>
          </div>
        )}
      </Card>
    </div>
  )
}

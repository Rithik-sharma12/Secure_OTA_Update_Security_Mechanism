'use client'

import React from 'react'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Key, Copy, Eye, EyeOff, RotateCcw, Trash2, CheckCircle2 } from 'lucide-react'

type VaultKeyStatus = 'active' | 'revoked'

type VaultKeyRecord = {
  id: string
  alias: string
  type: 'Ed25519'
  keySize: number
  fingerprint: string
  status: VaultKeyStatus
  createdAt: Date
  usageCount: number
  lastUsed: Date | null
  nextRotationAt: Date
}

type StoredVaultKeyRecord = Omit<VaultKeyRecord, 'createdAt' | 'lastUsed' | 'nextRotationAt'> & {
  createdAt: string
  lastUsed: string | null
  nextRotationAt: string
}

const KEY_VAULT_STORAGE_KEY = 'secure_ota_key_vault_records_v1'

function toLocalDateTag(date: Date) {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

function toDisplayDate(date: Date) {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

function buildFingerprint() {
  const randomHex = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replace(/-/g, '').toUpperCase()
    : `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`.toUpperCase()

  return randomHex.padEnd(48, '0').slice(0, 48)
}

function createVaultKey(alias: string): VaultKeyRecord {
  const now = new Date()
  const nextRotationAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000)

  return {
    id: typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `key-${Date.now().toString(16)}`,
    alias,
    type: 'Ed25519',
    keySize: 256,
    fingerprint: buildFingerprint(),
    status: 'active',
    createdAt: now,
    usageCount: 0,
    lastUsed: null,
    nextRotationAt,
  }
}

function hydrateStoredKeys(raw: unknown): VaultKeyRecord[] {
  if (!Array.isArray(raw)) {
    return []
  }

  return raw
    .map((item) => {
      const record = item as Partial<StoredVaultKeyRecord>
      if (!record.id || !record.alias || !record.fingerprint) {
        return null
      }

      return {
        id: String(record.id),
        alias: String(record.alias),
        type: 'Ed25519',
        keySize: Number(record.keySize || 256),
        fingerprint: String(record.fingerprint),
        status: record.status === 'revoked' ? 'revoked' : 'active',
        createdAt: new Date(record.createdAt || Date.now()),
        usageCount: Number(record.usageCount || 0),
        lastUsed: record.lastUsed ? new Date(record.lastUsed) : null,
        nextRotationAt: new Date(record.nextRotationAt || Date.now()),
      } satisfies VaultKeyRecord
    })
    .filter((record): record is VaultKeyRecord => Boolean(record))
}

function serializeKeys(records: VaultKeyRecord[]): StoredVaultKeyRecord[] {
  return records.map((record) => ({
    ...record,
    createdAt: record.createdAt.toISOString(),
    lastUsed: record.lastUsed ? record.lastUsed.toISOString() : null,
    nextRotationAt: record.nextRotationAt.toISOString(),
  }))
}

function getNextAlias(existing: VaultKeyRecord[]) {
  const baseAlias = `Vault Key ${toLocalDateTag(new Date())}`
  if (!existing.some((record) => record.alias === baseAlias)) {
    return baseAlias
  }

  let suffix = 2
  while (existing.some((record) => record.alias === `${baseAlias} (${suffix})`)) {
    suffix += 1
  }

  return `${baseAlias} (${suffix})`
}

export default function KeyVaultPage() {
  const [keys, setKeys] = React.useState<VaultKeyRecord[]>([])
  const [selectedKeyId, setSelectedKeyId] = React.useState<string | null>(null)
  const [showFullFingerprint, setShowFullFingerprint] = React.useState(false)
  const [message, setMessage] = React.useState<string | null>(null)

  React.useEffect(() => {
    try {
      const raw = window.localStorage.getItem(KEY_VAULT_STORAGE_KEY)
      const hydrated = hydrateStoredKeys(raw ? JSON.parse(raw) : [])

      if (hydrated.length > 0) {
        setKeys(hydrated)
        setSelectedKeyId(hydrated[0].id)
        return
      }
    } catch {
      // If state is malformed, fallback to default key provisioning.
    }

    const defaultKey = createVaultKey(`Vault Key ${toLocalDateTag(new Date())}`)
    setKeys([defaultKey])
    setSelectedKeyId(defaultKey.id)
  }, [])

  React.useEffect(() => {
    if (keys.length === 0) {
      return
    }

    window.localStorage.setItem(KEY_VAULT_STORAGE_KEY, JSON.stringify(serializeKeys(keys)))
  }, [keys])

  React.useEffect(() => {
    if (keys.length === 0) {
      setSelectedKeyId(null)
      return
    }

    if (!selectedKeyId || !keys.some((record) => record.id === selectedKeyId)) {
      setSelectedKeyId(keys[0].id)
    }
  }, [keys, selectedKeyId])

  const selectedKey = keys.find((record) => record.id === selectedKeyId) || null

  const handleGenerateKey = () => {
    const alias = getNextAlias(keys)
    const nextKey = createVaultKey(alias)

    setKeys((current) => [
      nextKey,
      ...current.map((record) => ({
        ...record,
        status: 'revoked' as const,
      })),
    ])
    setSelectedKeyId(nextKey.id)
    setShowFullFingerprint(false)
    setMessage(`${alias} created.`)
  }

  const handleOpenKey = (keyId: string) => {
    const match = keys.find((record) => record.id === keyId)
    if (!match) {
      return
    }

    setSelectedKeyId(match.id)
    setShowFullFingerprint(false)
    setMessage(`Opened ${match.alias}.`)
  }

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setMessage('Fingerprint copied to clipboard.')
    } catch {
      setMessage('Clipboard access failed.')
    }
  }

  const handleRotate = (keyId: string) => {
    const rotatedAt = new Date()
    const nextRotationAt = new Date(rotatedAt.getTime() + 90 * 24 * 60 * 60 * 1000)

    setKeys((current) => current.map((record) => {
      if (record.id !== keyId) {
        return record
      }

      return {
        ...record,
        usageCount: record.usageCount + 1,
        lastUsed: rotatedAt,
        nextRotationAt,
      }
    }))

    setMessage('Rotation metadata updated.')
  }

  const handleDelete = (keyId: string) => {
    setKeys((current) => current.filter((record) => record.id !== keyId))
    setMessage('Revoked key removed from vault list.')
  }

  const activeCount = keys.filter((record) => record.status === 'active').length
  const totalUsage = keys.reduce((sum, record) => sum + record.usageCount, 0)
  const rotationDue = keys.filter((record) => record.status === 'active' && record.nextRotationAt.getTime() <= Date.now()).length

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Key Vault</h1>
          <p className="text-slate-600 dark:text-slate-400 mt-1">
            Manage Ed25519 cryptographic keys for firmware signing
          </p>
        </div>
        <Button onClick={handleGenerateKey}>
          <Key className="w-4 h-4 mr-2" />
          Generate New Key
        </Button>
      </div>

      {message && <p className="text-sm text-blue-700 dark:text-blue-300">{message}</p>}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Active Keys</p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{activeCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Total Usage</p>
          <p className="text-3xl font-bold text-slate-900 dark:text-white">{totalUsage}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Rotation Due</p>
          <p className="text-lg font-bold text-yellow-600 dark:text-yellow-400">{rotationDue}</p>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Key Alias</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Fingerprint</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Status</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Usage</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Last Used</th>
                <th className="text-left px-6 py-3 font-semibold text-slate-900 dark:text-white">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-900/50">
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">{key.alias}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">{key.id}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded font-mono text-slate-600 dark:text-slate-300">
                        {key.fingerprint.slice(0, 16)}...
                      </code>
                      <button
                        className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                        title="Copy fingerprint"
                        onClick={() => void handleCopy(key.fingerprint)}
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      key.status === 'active'
                        ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}>
                      {key.status.charAt(0).toUpperCase() + key.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                    {key.usageCount} times
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600 dark:text-slate-400">
                    {key.lastUsed ? toDisplayDate(key.lastUsed) : 'Never'}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-2">
                      <button
                        className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                        title="View"
                        onClick={() => handleOpenKey(key.id)}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      {key.status === 'active' && (
                        <button
                          className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                          title="Rotate"
                          onClick={() => handleRotate(key.id)}
                        >
                          <RotateCcw className="w-4 h-4" />
                        </button>
                      )}
                      {key.status !== 'active' && (
                        <button
                          className="p-1 text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                          title="Delete"
                          onClick={() => handleDelete(key.id)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Key Metadata</h2>
          {selectedKey ? (
            <div className="space-y-4">
              <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Alias</p>
                <p className="text-sm font-medium text-slate-900 dark:text-white">{selectedKey.alias}</p>
              </div>
              <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Type</p>
                <p className="text-sm font-medium text-slate-900 dark:text-white">{selectedKey.type}</p>
              </div>
              <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Key Size</p>
                <p className="text-sm font-medium text-slate-900 dark:text-white">{selectedKey.keySize} bits</p>
              </div>
              <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide">Full Fingerprint</p>
                  <button
                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                    onClick={() => setShowFullFingerprint((current) => !current)}
                    title={showFullFingerprint ? 'Hide fingerprint' : 'Show fingerprint'}
                  >
                    {showFullFingerprint ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-xs font-mono bg-slate-100 dark:bg-slate-900 p-3 rounded text-slate-700 dark:text-slate-300 break-all">
                  {showFullFingerprint ? selectedKey.fingerprint : `${selectedKey.fingerprint.slice(0, 16)}••••••••••••••••••••••••••••`}
                </p>
              </div>
              <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Created</p>
                <p className="text-sm font-medium text-slate-900 dark:text-white">{toDisplayDate(selectedKey.createdAt)}</p>
              </div>
              <div>
                <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-1">Next Rotation</p>
                <p className="text-sm font-medium text-slate-900 dark:text-white">{toDisplayDate(selectedKey.nextRotationAt)}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-600 dark:text-slate-400">No key selected.</p>
          )}
        </Card>

        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">CI/CD Integration</h2>
          <div className="space-y-4">
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Environment Variables</p>
              <code className="text-xs bg-slate-100 dark:bg-slate-900 px-3 py-2 rounded font-mono text-slate-700 dark:text-slate-300 block break-all">
                OTA_RELEASE_KEY_FINGERPRINT={selectedKey ? selectedKey.fingerprint.slice(0, 16) : 'UNSET'}
              </code>
            </div>
            <div className="pb-4 border-b border-slate-200 dark:border-slate-700">
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">GitHub Secrets</p>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <span className="text-xs text-slate-600 dark:text-slate-400">OTA_RELEASE_KEY</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                  <span className="text-xs text-slate-600 dark:text-slate-400">OTA_RELEASE_KEY_PASS</span>
                </div>
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-600 dark:text-slate-400 uppercase tracking-wide mb-2">Last CI/CD Run</p>
              <p className="text-sm text-slate-700 dark:text-slate-300">
                {selectedKey?.lastUsed ? toDisplayDate(selectedKey.lastUsed) : 'No signing run yet'}
                <span className="ml-2 px-2 py-1 rounded-full bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300 text-xs font-semibold">
                  Ready
                </span>
              </p>
            </div>
          </div>
        </Card>
      </div>

      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Key Rotation Schedule</h2>
        <div className="space-y-3">
          {keys.length === 0 && (
            <p className="text-sm text-slate-600 dark:text-slate-400">No key records available.</p>
          )}
          {keys.map((record) => {
            const due = record.nextRotationAt.getTime() <= Date.now()
            return (
              <div
                key={record.id}
                className={`flex items-center gap-3 p-3 rounded-lg ${
                  due ? 'bg-yellow-50 dark:bg-yellow-950/20' : 'bg-slate-50 dark:bg-slate-900/50'
                }`}
              >
                <div
                  className={`w-4 h-4 rounded-full flex-shrink-0 ${
                    due ? 'bg-yellow-500' : 'bg-slate-400'
                  }`}
                />
                <div className="flex-1">
                  <p className={`text-sm font-medium ${
                    due ? 'text-yellow-900 dark:text-yellow-100' : 'text-slate-600 dark:text-slate-400'
                  }`}>
                    {record.alias}
                  </p>
                </div>
                <p className={`text-sm font-mono ${
                  due ? 'text-yellow-700 dark:text-yellow-300' : 'text-slate-500'
                }`}>
                  {toLocalDateTag(record.nextRotationAt)}
                </p>
              </div>
            )
          })}
        </div>
      </Card>
    </div>
  )
}

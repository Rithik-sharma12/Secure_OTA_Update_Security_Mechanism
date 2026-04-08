import { usePipeline } from '@/lib/data-hooks'
import { Card } from '@/components/ui/card'
import { CheckCircle2, Clock, AlertCircle, BarChart3 } from 'lucide-react'
import { cn } from '@/lib/utils'

export default function PipelinePage() {
  const stages = usePipeline()

  const getStageIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-6 h-6 text-green-500" />
      case 'running':
        return <BarChart3 className="w-6 h-6 text-blue-500 animate-pulse" />
      case 'pending':
        return <Clock className="w-6 h-6 text-slate-400" />
      case 'failed':
        return <AlertCircle className="w-6 h-6 text-red-500" />
      default:
        return null
    }
  }

  const getStageColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/20 border-green-500'
      case 'running':
        return 'bg-blue-500/20 border-blue-500'
      case 'pending':
        return 'bg-slate-500/20 border-slate-500'
      case 'failed':
        return 'bg-red-500/20 border-red-500'
      default:
        return 'bg-slate-500/20 border-slate-500'
    }
  }

  return (
    <div className="space-y-6">
      {/* Overview */}
      <Card className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Release Tag</p>
            <p className="text-2xl font-bold text-slate-900 dark:text-white font-mono">v2024.02.15</p>
          </div>
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Total Duration</p>
            <p className="text-2xl font-bold text-slate-900 dark:text-white">
              {stages.reduce((sum, s) => sum + (s.duration || 0), 0)} seconds
            </p>
          </div>
          <div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Status</p>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-blue-500 rounded-full animate-pulse" />
              <p className="text-lg font-semibold text-slate-900 dark:text-white">In Progress</p>
            </div>
          </div>
        </div>
      </Card>

      {/* Pipeline Stages */}
      <div className="space-y-4">
        {stages.map((stage, index) => (
          <div key={stage.name}>
            <Card className={cn('p-6 border-l-4 transition-all', getStageColor(stage.status))}>
              <div className="space-y-4">
                {/* Stage Header */}
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4 flex-1">
                    <div className="mt-0.5">
                      {getStageIcon(stage.status)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                          {index + 1}. {stage.name}
                        </h3>
                        <span className={cn(
                          'px-2 py-1 rounded text-xs font-medium',
                          stage.status === 'completed' && 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300',
                          stage.status === 'running' && 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300',
                          stage.status === 'pending' && 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300',
                          stage.status === 'failed' && 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300',
                        )}>
                          {stage.status.charAt(0).toUpperCase() + stage.status.slice(1)}
                        </span>
                      </div>
                      {stage.duration && (
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          Duration: {stage.duration}s
                        </p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Stage Output */}
                {stage.output && (
                  <div className="bg-slate-900 dark:bg-slate-950 rounded font-mono text-xs text-slate-300 p-4 max-h-48 overflow-y-auto">
                    <pre className="whitespace-pre-wrap break-words">{stage.output}</pre>
                  </div>
                )}

                {/* Progress Bar */}
                {stage.status === 'running' && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-600 dark:text-slate-400">Uploading binaries</span>
                      <span className="text-slate-600 dark:text-slate-400">86%</span>
                    </div>
                    <div className="w-full bg-slate-700 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
                      <div className="bg-blue-500 h-full rounded-full w-[86%] transition-all" />
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {/* Connector */}
            {index < stages.length - 1 && (
              <div className="flex justify-center py-2">
                <div className="w-0.5 h-6 bg-slate-300 dark:bg-slate-700" />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Build Artifacts */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Build Artifacts</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">firmware-atmega.bin</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">32.3 KB • SHA256: abc123...</p>
            </div>
            <button className="px-3 py-1 text-sm rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white transition-colors">
              Download
            </button>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">firmware-esp32.bin</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">64.0 KB • SHA256: def456...</p>
            </div>
            <button className="px-3 py-1 text-sm rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white transition-colors">
              Download
            </button>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">firmware-stm32.bin</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">98.3 KB • SHA256: ghi789...</p>
            </div>
            <button className="px-3 py-1 text-sm rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white transition-colors">
              Download
            </button>
          </div>
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
            <div>
              <p className="font-medium text-slate-900 dark:text-white">firmware-nrf52.bin</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">120.0 KB • SHA256: jkl012...</p>
            </div>
            <button className="px-3 py-1 text-sm rounded bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white transition-colors">
              Download
            </button>
          </div>
        </div>
      </Card>
    </div>
  )
}

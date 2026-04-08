import { useReleases, formatDate, formatBytes } from '@/lib/data-hooks'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { CheckCircle2, Download, Tag, Calendar, FileSize } from 'lucide-react'

export default function ReleasesPage() {
  const releases = useReleases()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Releases</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          {releases.length} published releases
        </p>
      </div>

      {/* Release List */}
      <div className="space-y-4">
        {releases.map((release, index) => (
          <Card key={release.version} className="p-6">
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <Tag className="w-5 h-5 text-slate-400" />
                    <h3 className="text-xl font-bold text-slate-900 dark:text-white font-mono">
                      {release.tag}
                    </h3>
                    {release.signatureVerified && (
                      <div className="flex items-center gap-1 px-2 py-1 rounded-full bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300 text-xs font-medium">
                        <CheckCircle2 className="w-3 h-3" />
                        Verified
                      </div>
                    )}
                    {index === 0 && (
                      <div className="px-2 py-1 rounded-full bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 text-xs font-bold uppercase">
                        Latest
                      </div>
                    )}
                  </div>
                  <p className="text-sm text-slate-600 dark:text-slate-400 font-mono">
                    {release.signature.substring(0, 40)}...
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">Released</p>
                  <p className="font-medium text-slate-900 dark:text-white">
                    {new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: 'numeric' }).format(release.releaseDate)}
                  </p>
                </div>
              </div>

              {/* Description */}
              <p className="text-sm text-slate-700 dark:text-slate-300">
                {release.releaseNotes}
              </p>

              {/* Metadata Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex items-center gap-2 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                  <FileSize className="w-4 h-4 text-slate-400" />
                  <div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">File Size</p>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">
                      {formatBytes(release.fileSize)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                  <Calendar className="w-4 h-4 text-slate-400" />
                  <div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Checksum</p>
                    <p className="text-xs font-mono text-slate-600 dark:text-slate-400">
                      {release.checksum.substring(0, 16)}...
                    </p>
                  </div>
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-900/50">
                  <div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Rollout</p>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">
                      {release.rolloutPercentage}%
                    </p>
                  </div>
                  <div className="w-20 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-teal-500 rounded-full transition-all"
                      style={{ width: `${release.rolloutPercentage}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Rollout Stages */}
              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700">
                <p className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Rollout Strategy</p>
                <div className="space-y-2">
                  {[
                    { stage: 1, percentage: 10, duration: '1h', complete: release.rolloutPercentage >= 10 },
                    { stage: 2, percentage: 50, duration: '4h', complete: release.rolloutPercentage >= 50 },
                    { stage: 3, percentage: 100, duration: '24h', complete: release.rolloutPercentage >= 100 },
                  ].map((stage) => (
                    <div key={stage.stage} className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                        stage.complete
                          ? 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300'
                          : 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
                      }`}>
                        {stage.stage}
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-slate-900 dark:text-white">
                          Rollout Stage {stage.stage}: {stage.percentage}%
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {stage.duration}
                        </p>
                      </div>
                      {stage.complete && (
                        <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div className="flex flex-wrap gap-2">
                <Button size="sm">
                  <Download className="w-4 h-4 mr-2" />
                  Download Release
                </Button>
                <Button variant="outline" size="sm">
                  View Release Notes
                </Button>
                <Button variant="outline" size="sm">
                  View Signature
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}

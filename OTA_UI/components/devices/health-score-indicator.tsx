import { getHealthCategory } from '@/lib/data-hooks'
import { cn } from '@/lib/utils'

interface HealthScoreIndicatorProps {
  score: number
  showLabel?: boolean
}

export function HealthScoreIndicator({ score, showLabel = true }: HealthScoreIndicatorProps) {
  const category = getHealthCategory(score)

  const colorClasses = {
    critical: 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300',
    warning: 'bg-yellow-100 dark:bg-yellow-950 text-yellow-700 dark:text-yellow-300',
    good: 'bg-green-100 dark:bg-green-950 text-green-700 dark:text-green-300',
    excellent: 'bg-teal-100 dark:bg-teal-950 text-teal-700 dark:text-teal-300',
  }

  const categoryLabels = {
    critical: 'Critical',
    warning: 'Warning',
    good: 'Good',
    excellent: 'Excellent',
  }

  return (
    <div className="flex items-center gap-2">
      <div className={cn('px-3 py-1.5 rounded-full text-sm font-medium text-center min-w-12', colorClasses[category])}>
        {score}
      </div>
      {showLabel && (
        <span className="text-sm text-slate-600 dark:text-slate-400">
          {categoryLabels[category]}
        </span>
      )}
    </div>
  )
}

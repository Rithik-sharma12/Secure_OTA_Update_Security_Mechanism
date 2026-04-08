import { cn } from '@/lib/utils'

interface HealthProgressBarProps {
  value: number
  label?: string
  showPercentage?: boolean
  size?: 'sm' | 'md' | 'lg'
}

export function HealthProgressBar({
  value,
  label,
  showPercentage = true,
  size = 'md',
}: HealthProgressBarProps) {
  // Clamp value between 0-100
  const clampedValue = Math.min(Math.max(value, 0), 100)

  // Determine color based on health score
  let colorClass = 'bg-red-500'
  if (clampedValue >= 80) colorClass = 'bg-teal-500'
  else if (clampedValue >= 60) colorClass = 'bg-green-500'
  else if (clampedValue >= 40) colorClass = 'bg-yellow-500'

  const heightClass = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  }[size]

  return (
    <div className="space-y-2">
      {(label || showPercentage) && (
        <div className="flex items-center justify-between">
          {label && <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{label}</span>}
          {showPercentage && <span className="text-sm font-semibold text-slate-900 dark:text-white">{clampedValue}%</span>}
        </div>
      )}
      <div className={cn('w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden', heightClass)}>
        <div
          className={cn('transition-all duration-500', colorClass, heightClass)}
          style={{ width: `${clampedValue}%` }}
        />
      </div>
    </div>
  )
}

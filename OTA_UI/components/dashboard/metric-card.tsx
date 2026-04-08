import { ReactNode } from 'react'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface MetricCardProps {
  title: string
  value: number | string
  description?: string
  icon?: ReactNode
  trend?: {
    value: number
    direction: 'up' | 'down'
  }
  colorClass?: string
}

export function MetricCard({
  title,
  value,
  description,
  icon,
  trend,
  colorClass = 'text-teal-600 dark:text-teal-400',
}: MetricCardProps) {
  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{title}</p>
          <div className="flex items-baseline gap-2 mt-2">
            <div className={cn('text-3xl font-bold', colorClass)}>
              {value}
            </div>
            {trend && (
              <div className={cn('text-sm font-medium', trend.direction === 'up' ? 'text-green-600' : 'text-red-600')}>
                {trend.direction === 'up' ? '↑' : '↓'} {trend.value}%
              </div>
            )}
          </div>
          {description && (
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">{description}</p>
          )}
        </div>
        {icon && (
          <div className={cn('p-3 rounded-lg', colorClass.replace('text-', 'bg-').replace('dark:', 'dark:bg-') + '/10')}>
            <div className={colorClass}>
              {icon}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}

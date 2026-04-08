import { architectureBg, architectureText, Architecture } from '@/lib/mock-data'
import { cn } from '@/lib/utils'
import { Cpu } from 'lucide-react'

interface ArchitectureBadgeProps {
  architecture: Architecture
  showIcon?: boolean
  size?: 'sm' | 'md'
}

export function ArchitectureBadge({
  architecture,
  showIcon = true,
  size = 'md',
}: ArchitectureBadgeProps) {
  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1.5 text-sm',
  }

  return (
    <div className={cn('inline-flex items-center gap-2 rounded-full border', architectureBg[architecture], architectureText[architecture], sizeClasses[size])}>
      {showIcon && <Cpu className="w-3 h-3" />}
      <span className="font-medium">{architecture}</span>
    </div>
  )
}

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  title: string;
  value: string | number;
  unit?: string;
  description?: string;
  icon?: React.ReactNode;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  className?: string;
}

const variantStyles = {
  default: 'text-foreground',
  success: 'text-chart-1',
  warning: 'text-yellow-500',
  danger: 'text-chart-4',
  info: 'text-blue-500',
};

export function MetricCard({
  title,
  value,
  unit,
  description,
  icon,
  trend,
  variant = 'default',
  className,
}: MetricCardProps) {
  return (
    <Card className={cn('glass border-border/50 hover:border-border/80 transition-all', className)}>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
        <CardDescription className="text-xs uppercase tracking-wider">
          {title}
        </CardDescription>
        {icon && <div className={cn('text-xl', variantStyles[variant])}>{icon}</div>}
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-baseline gap-2">
          <span className={cn('text-3xl font-bold', variantStyles[variant])}>
            {value}
          </span>
          {unit && <span className="text-sm text-foreground/60">{unit}</span>}
        </div>
        {(trend || description) && (
          <div className="flex items-center justify-between">
            {description && (
              <p className="text-xs text-foreground/60">{description}</p>
            )}
            {trend && (
              <span className={cn('text-xs font-semibold', 
                trend.isPositive ? 'text-chart-1' : 'text-chart-4'
              )}>
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

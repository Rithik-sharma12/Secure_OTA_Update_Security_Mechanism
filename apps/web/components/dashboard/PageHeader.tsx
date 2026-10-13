import React from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface PageHeaderProps {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: {
    label: string;
    onClick: () => void;
    variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost';
  };
  badge?: {
    label: string;
    variant?: 'default' | 'secondary' | 'destructive' | 'outline';
  };
}

export function PageHeader({ title, description, icon, action, badge }: PageHeaderProps) {
  return (
    <div className="flex items-center justify-between mb-8">
      <div className="flex items-center gap-3">
        {icon && <div className="text-accent">{icon}</div>}
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-3xl font-bold text-foreground">{title}</h1>
            {badge && (
              <Badge variant={badge.variant as any} className="ml-2">
                {badge.label}
              </Badge>
            )}
          </div>
          {description && (
            <p className="text-foreground/70 mt-1">{description}</p>
          )}
        </div>
      </div>
      {action && (
        <Button
          onClick={action.onClick}
          variant={action.variant as any}
          className="whitespace-nowrap"
        >
          {action.label}
        </Button>
      )}
    </div>
  );
}

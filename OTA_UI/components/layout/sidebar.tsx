'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { navIcons, navItems } from './nav-icons'
import { cn } from '@/lib/utils'
import { Shield } from 'lucide-react'

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="hidden md:fixed md:inset-y-0 md:z-50 md:flex md:w-56 md:flex-col bg-slate-900 dark:bg-slate-950">
      {/* Logo Section */}
      <div className="flex items-center gap-2 px-6 py-5 border-b border-slate-700">
        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-teal-500 to-cyan-500">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div className="flex-1">
          <div className="text-sm font-semibold text-white">OTA Control</div>
          <div className="text-xs text-slate-400">Firmware Hub</div>
        </div>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <div className="space-y-8">
          {navItems.map((group) => (
            <div key={group.group}>
              <div className="px-3 py-2 text-xs font-semibold text-slate-400 uppercase tracking-wide">
                {group.group}
              </div>
              <div className="space-y-1">
                {group.items.map((item) => {
                  const IconComponent = navIcons[item.icon as keyof typeof navIcons]
                  const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
                  
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                        'flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-slate-700 text-teal-400'
                          : 'text-slate-300 hover:bg-slate-800 hover:text-slate-100'
                      )}
                    >
                      <IconComponent className="w-4 h-4" />
                      <span>{item.name}</span>
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-700">
        <div className="text-xs text-slate-400">
          <div className="font-semibold text-slate-300">v1.0.0</div>
          <div>Firmware Control Center</div>
        </div>
      </div>
    </aside>
  )
}

'use client'

import { Menu, Bell, User, LogOut } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { usePathname } from 'next/navigation'

const breadcrumbMap: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/devices': 'Devices',
  '/event-logs': 'Event Logs',
  '/pipeline': 'Pipeline',
  '/releases': 'Releases',
  '/manifest': 'Manifest',
  '/tcv-engine': 'TCV Engine',
  '/ash-monitor': 'ASH Monitor',
  '/key-vault': 'Key Vault',
  '/settings': 'Settings',
}

export function Header() {
  const pathname = usePathname()
  const title = breadcrumbMap[pathname] || 'OTA Control Center'

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
      <div className="flex items-center justify-between h-16 px-4 sm:px-6 lg:px-8">
        {/* Left side - Mobile menu button and title */}
        <div className="flex items-center gap-4 flex-1">
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
          >
            <Menu className="w-5 h-5" />
          </Button>
          <div>
            <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
              {title}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Secure OTA Update Management
            </p>
          </div>
        </div>

        {/* Right side - Notifications and user menu */}
        <div className="flex items-center gap-2 sm:gap-4">
          <Button
            variant="ghost"
            size="icon"
            className="relative"
          >
            <Bell className="w-5 h-5" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon">
                <User className="w-5 h-5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <div className="px-2 py-1.5">
                <p className="text-sm font-medium text-slate-900 dark:text-white">John Admin</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">admin@otacontrol.local</p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <User className="w-4 h-4 mr-2" />
                <span>Profile</span>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <span>Settings</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <LogOut className="w-4 h-4 mr-2" />
                <span>Logout</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}

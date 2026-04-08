import { Sidebar } from './sidebar'
import { Header } from './header'

export function MainLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col min-h-screen">
      {/* Desktop Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex flex-col flex-1 md:ml-56">
        {/* Header */}
        <Header />

        {/* Content */}
        <main className="flex-1 overflow-auto bg-slate-50 dark:bg-slate-900">
          <div className="p-4 sm:p-6 lg:p-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

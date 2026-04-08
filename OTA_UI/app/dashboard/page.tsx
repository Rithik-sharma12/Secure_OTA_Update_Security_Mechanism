import { useStatistics } from '@/lib/data-hooks'
import { mockDevices } from '@/lib/mock-data'
import { MetricCard } from '@/components/dashboard/metric-card'
import { HealthProgressBar } from '@/components/dashboard/health-progress-bar'
import { Card } from '@/components/ui/card'
import { Activity, AlertCircle, CheckCircle2, Zap } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

export default function DashboardPage() {
  const stats = useStatistics()

  // Architecture distribution data
  const architectureData = [
    {
      name: 'ATmega328P',
      value: mockDevices.filter(d => d.architecture === 'ATmega328P').length,
      color: '#FF6B35',
    },
    {
      name: 'ESP8266/ESP32',
      value: mockDevices.filter(d => d.architecture === 'ESP8266/ESP32').length,
      color: '#0A84FF',
    },
    {
      name: 'STM32',
      value: mockDevices.filter(d => d.architecture === 'STM32').length,
      color: '#A855F7',
    },
    {
      name: 'nRF52840',
      value: mockDevices.filter(d => d.architecture === 'nRF52840').length,
      color: '#F59E0B',
    },
  ]

  // Status distribution data
  const statusData = [
    {
      name: 'Online',
      value: stats.onlineDevices,
      color: '#10b981',
    },
    {
      name: 'Pending',
      value: stats.pendingUpdates,
      color: '#f59e0b',
    },
    {
      name: 'Quarantined',
      value: stats.quarantinedDevices,
      color: '#ef4444',
    },
  ]

  return (
    <div className="space-y-8">
      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Devices"
          value={stats.totalDevices}
          description="Across all architectures"
          icon={<Zap className="w-5 h-5" />}
          colorClass="text-blue-600 dark:text-blue-400"
          trend={{ value: 2, direction: 'up' }}
        />
        <MetricCard
          title="Online Devices"
          value={stats.onlineDevices}
          description={`${Math.round((stats.onlineDevices / stats.totalDevices) * 100)}% uptime`}
          icon={<CheckCircle2 className="w-5 h-5" />}
          colorClass="text-green-600 dark:text-green-400"
        />
        <MetricCard
          title="Updates Pending"
          value={stats.pendingUpdates}
          description="Awaiting deployment"
          icon={<Activity className="w-5 h-5" />}
          colorClass="text-yellow-600 dark:text-yellow-400"
        />
        <MetricCard
          title="Quarantined"
          value={stats.quarantinedDevices}
          description="Health check failed"
          icon={<AlertCircle className="w-5 h-5" />}
          colorClass="text-red-600 dark:text-red-400"
        />
      </div>

      {/* Health Overview */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Fleet Health Overview</h2>
        <div className="space-y-6">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Average Health Score</span>
              <span className="text-2xl font-bold text-slate-900 dark:text-white">{stats.avgHealthScore}</span>
            </div>
            <HealthProgressBar value={stats.avgHealthScore} showPercentage={false} size="lg" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Update Completion Rate</span>
              <span className="text-2xl font-bold text-slate-900 dark:text-white">{stats.updateCompletionRate}%</span>
            </div>
            <HealthProgressBar value={stats.updateCompletionRate} showPercentage={false} size="lg" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">TCV Pass Rate</span>
              <span className="text-2xl font-bold text-slate-900 dark:text-white">{stats.tcvPassRate}%</span>
            </div>
            <HealthProgressBar value={stats.tcvPassRate} showPercentage={false} size="lg" />
          </div>
        </div>
      </Card>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Architecture Distribution */}
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Device Distribution by Architecture</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={architectureData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {architectureData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* Status Distribution */}
        <Card className="p-6">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">Device Status Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={statusData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {statusData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* System Status */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6">System Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center gap-3 p-3 rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-900">
            <div className="w-3 h-3 bg-green-500 rounded-full" />
            <div>
              <p className="text-sm font-medium text-green-900 dark:text-green-100">API Server</p>
              <p className="text-xs text-green-700 dark:text-green-200">Operational</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-900">
            <div className="w-3 h-3 bg-green-500 rounded-full" />
            <div>
              <p className="text-sm font-medium text-green-900 dark:text-green-100">Signature Engine</p>
              <p className="text-xs text-green-700 dark:text-green-200">Operational</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-900">
            <div className="w-3 h-3 bg-green-500 rounded-full" />
            <div>
              <p className="text-sm font-medium text-green-900 dark:text-green-100">TCV System</p>
              <p className="text-xs text-green-700 dark:text-green-200">Operational</p>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}

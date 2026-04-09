'use client';

import React from 'react';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { TrendingUp, TrendingDown, AlertCircle, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { formatNumber, formatUtcDate, formatUtcTime } from '@/lib/formatters';
import { useRuntimeSnapshot } from '@/lib/runtime-data';

const weekLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function MetricCard({
  title,
  value,
  change,
  trend,
  icon: Icon,
}: {
  title: string;
  value: string | number;
  change: number;
  trend: 'up' | 'down' | 'stable';
  icon: React.ReactNode;
}) {
  return (
    <Card className="glass border-border/50">
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm text-foreground/70 mb-1">{title}</p>
            <p className="text-2xl font-bold text-foreground">{value}</p>
            <p className={`text-xs mt-2 flex items-center gap-1 ${
              trend === 'down' ? 'text-chart-4' : 'text-chart-1'
            }`}>
              {trend === 'down' ? <TrendingDown className="w-3 h-3" /> : <TrendingUp className="w-3 h-3" />}
              {Math.abs(change)}% {trend === 'down' ? 'down' : 'up'} from last week
            </p>
          </div>
          <div className="p-3 bg-primary/20 rounded-lg text-primary">
            {Icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const { snapshot, isLoading } = useRuntimeSnapshot();

  const onlineCount = snapshot.devices.filter((device) => device.status === 'online').length;
  const offlineCount = snapshot.devices.filter((device) => device.status === 'offline' || device.status === 'error').length;
  const updatingCount = snapshot.devices.filter((device) => device.status === 'updating').length;
  const needsUpdateCount = snapshot.devices.filter((device) => device.firmwareVersion !== device.latestVersion).length;
  const recentEvents = snapshot.events.slice(0, 5);
  const latestRelease = snapshot.releases[0];

  const metricsData = React.useMemo(() => {
    const counts = weekLabels.map((label) => ({ name: label, successful: 0, failed: 0 }));

    snapshot.events.forEach((event) => {
      const eventDay = event.timestamp.getDay();
      const row = counts.find((item) => item.name === weekLabels[eventDay]);
      if (!row) {
        return;
      }

      if (event.severity === 'success') {
        row.successful += 1;
      } else if (event.severity === 'error' || event.severity === 'warning') {
        row.failed += 1;
      }
    });

    return counts;
  }, [snapshot.events]);

  const deviceStatusData = React.useMemo(
    () => [
      { name: 'Online', value: onlineCount, color: '#4CAF50' },
      { name: 'Offline', value: offlineCount, color: '#F44336' },
      { name: 'Updating', value: updatingCount, color: '#FF9800' },
    ],
    [offlineCount, onlineCount, updatingCount]
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-foreground">Dashboard</h1>
        <p className="text-foreground/70 mt-1">
          {isLoading ? 'Loading live gateway telemetry...' : 'Live telemetry from edge gateway and OTA runtime.'}
        </p>
        {!snapshot.connection.reachable && snapshot.connection.error && (
          <p className="text-sm text-chart-4 mt-2">{snapshot.connection.error}</p>
        )}
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Online Devices"
          value={onlineCount}
          change={12}
          trend="up"
          icon={<CheckCircle className="w-5 h-5" />}
        />
        <MetricCard
          title="Offline Devices"
          value={offlineCount}
          change={5}
          trend="down"
          icon={<AlertCircle className="w-5 h-5" />}
        />
        <MetricCard
          title="Updating"
          value={updatingCount}
          change={0}
          trend="stable"
          icon={<TrendingUp className="w-5 h-5" />}
        />
        <MetricCard
          title="Updates Available"
          value={needsUpdateCount}
          change={8}
          trend="down"
          icon={<AlertCircle className="w-5 h-5" />}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Deployment Success Chart */}
        <Card className="glass border-border/50 lg:col-span-2">
          <CardHeader>
            <CardTitle>Deployment Success Rate</CardTitle>
            <CardDescription>Weekly firmware deployment performance</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={metricsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="name" stroke="rgba(255,255,255,0.5)" />
                <YAxis stroke="rgba(255,255,255,0.5)" />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(25,0,25,0.9)', border: '1px solid rgba(133,79,108,0.3)' }}
                  labelStyle={{ color: '#fbe4d8' }}
                />
                <Bar dataKey="successful" fill="#4CAF50" radius={[8, 8, 0, 0]} />
                <Bar dataKey="failed" fill="#F44336" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Device Status Pie Chart */}
        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle>Device Status</CardTitle>
            <CardDescription>Current device distribution</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={deviceStatusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {deviceStatusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(25,0,25,0.9)', border: '1px solid rgba(133,79,108,0.3)' }}
                  labelStyle={{ color: '#fbe4d8' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-4 space-y-2 text-sm">
              {deviceStatusData.map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-foreground/70">{item.name}</span>
                  </div>
                  <span className="font-semibold text-foreground">{item.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Events */}
        <Card className="glass border-border/50">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Recent Events</CardTitle>
              <CardDescription>Latest system activities</CardDescription>
            </div>
            <Button variant="outline" size="sm">View All</Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {recentEvents.map((event) => (
                <div key={event.id} className="flex items-start gap-3 pb-3 border-b border-border/50 last:border-0">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                    event.severity === 'success' ? 'bg-chart-1' :
                    event.severity === 'error' ? 'bg-chart-4' :
                    event.severity === 'warning' ? 'bg-chart-3' :
                    'bg-chart-2'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground">{event.title}</p>
                    <p className="text-xs text-foreground/50 mt-0.5 truncate">{event.description}</p>
                    <p className="text-xs text-foreground/40 mt-1">
                      {formatUtcTime(event.timestamp)}
                    </p>
                  </div>
                  <Badge 
                    variant="outline" 
                    className={`flex-shrink-0 ${
                      event.severity === 'success' ? 'bg-chart-1/20 text-chart-1' :
                      event.severity === 'error' ? 'bg-chart-4/20 text-chart-4' :
                      event.severity === 'warning' ? 'bg-chart-3/20 text-chart-3' :
                      'bg-chart-2/20 text-chart-2'
                    }`}
                  >
                    {event.severity}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Latest Release Info */}
        <Card className="glass border-border/50">
          <CardHeader>
            <CardTitle>Latest Release</CardTitle>
            <CardDescription>Firmware v{latestRelease?.version}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {latestRelease && (
              <>
                <div>
                  <p className="text-xs text-foreground/50 mb-1">Release Date</p>
                  <p className="text-sm font-medium text-foreground">
                    {formatUtcDate(latestRelease.releaseDate)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-foreground/50 mb-1">Description</p>
                  <p className="text-sm text-foreground/80">{latestRelease.description}</p>
                </div>
                <div>
                  <p className="text-xs text-foreground/50 mb-1">Downloads</p>
                  <p className="text-sm font-medium text-foreground">{formatNumber(latestRelease.downloadCount)}</p>
                </div>
                <div>
                  <p className="text-xs text-foreground/50 mb-2">Compatible Devices</p>
                  <div className="flex flex-wrap gap-2">
                    {latestRelease.compatible.map((device) => (
                      <Badge key={device} variant="secondary" className="bg-primary/20 text-primary">
                        {device}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Button className="w-full mt-2">View Release</Button>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

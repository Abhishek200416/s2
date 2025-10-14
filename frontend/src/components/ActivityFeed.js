import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Activity, AlertTriangle, CheckCircle, Zap, Clock } from 'lucide-react';

const ActivityFeed = ({ companyId }) => {
  const [activities, setActivities] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    if (companyId) {
      loadActivities();
    }
  }, [companyId]);

  useEffect(() => {
    if (!autoRefresh || !companyId) return;

    const interval = setInterval(() => {
      loadActivities();
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, companyId]);

  const loadActivities = async () => {
    try {
      const response = await api.get(`/activities?company_id=${companyId}&limit=20`);
      setActivities(response.data);
    } catch (error) {
      console.error('Failed to load activities:', error);
    }
  };

  const getActivityIcon = (type) => {
    switch (type) {
      case 'alert_received':
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      case 'incident_created':
        return <Zap className="w-4 h-4 text-cyan-400" />;
      case 'incident_resolved':
        return <CheckCircle className="w-4 h-4 text-emerald-400" />;
      default:
        return <Activity className="w-4 h-4 text-slate-400" />;
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
      medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
      critical: 'bg-red-500/20 text-red-300 border-red-500/30'
    };
    return colors[severity] || '';
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <Card className="bg-slate-900/50 border-slate-800" data-testid="activity-feed">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-emerald-400" />
              Live Activity Feed
            </CardTitle>
            <CardDescription className="text-slate-400 mt-1">
              Real-time operations monitoring
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {autoRefresh && (
              <div className="flex items-center gap-2 text-xs text-emerald-400">
                <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
                Live
              </div>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {activities.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <Clock className="w-8 h-8 mx-auto mb-2 text-slate-600" />
            <p>No recent activity</p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {activities.map((activity) => (
              <div
                key={activity.id}
                className="flex items-start gap-3 p-3 bg-slate-800/30 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors"
              >
                <div className="mt-0.5">{getActivityIcon(activity.type)}</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white">{activity.message}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-slate-500">{formatTime(activity.timestamp)}</span>
                    {activity.severity && (
                      <Badge className={`text-xs ${getSeverityColor(activity.severity)} border`}>
                        {activity.severity}
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;
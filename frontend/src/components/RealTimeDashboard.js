import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Activity, AlertCircle, CheckCircle, Clock, Filter, 
  RefreshCw, TrendingDown, Zap, Bell, MessageSquare,
  AlertTriangle, XCircle, Radio
} from 'lucide-react';
import { toast } from 'sonner';

const RealTimeDashboard = ({ companyId, companyName }) => {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  // Filters
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  // WebSocket
  const ws = useRef(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Load data
  const loadData = useCallback(async () => {
    try {
      const [alertsRes, incidentsRes, metricsRes] = await Promise.all([
        api.get(`/alerts?company_id=${companyId}&status=active`),
        api.get(`/incidents?company_id=${companyId}`),
        api.get(`/metrics/realtime?company_id=${companyId}`)
      ]);
      
      setAlerts(alertsRes.data);
      setIncidents(incidentsRes.data);
      setMetrics(metricsRes.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load data:', error);
      toast.error('Failed to load dashboard data');
      setLoading(false);
    }
  }, [companyId]);

  // WebSocket connection for real-time updates
  useEffect(() => {
    const backendUrl = process.env.REACT_APP_BACKEND_URL || '';
    const wsUrl = backendUrl.replace('http://', 'ws://').replace('https://', 'wss://') + '/ws';
    
    const connectWebSocket = () => {
      ws.current = new WebSocket(wsUrl);
      
      ws.current.onopen = () => {
        console.log('WebSocket connected');
        setWsConnected(true);
      };
      
      ws.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleWebSocketMessage(message);
      };
      
      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setWsConnected(false);
      };
      
      ws.current.onclose = () => {
        console.log('WebSocket disconnected');
        setWsConnected(false);
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
      };
    };
    
    connectWebSocket();
    
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const handleWebSocketMessage = (message) => {
    switch (message.type) {
      case 'alert_received':
        setAlerts(prev => [message.data, ...prev]);
        loadData(); // Refresh metrics
        if (message.data.severity === 'critical' || message.data.severity === 'high') {
          toast.error(`${message.data.severity.toUpperCase()} Alert: ${message.data.message}`);
          // Browser notification
          if (Notification.permission === 'granted') {
            new Notification('Alert Whisperer', {
              body: `${message.data.severity.toUpperCase()}: ${message.data.message}`,
              icon: '/favicon.ico'
            });
          }
        }
        break;
      
      case 'incident_created':
        setIncidents(prev => [message.data, ...prev]);
        toast.success(`New incident created: ${message.data.signature}`);
        loadData(); // Refresh metrics
        break;
      
      case 'incident_updated':
        setIncidents(prev => 
          prev.map(inc => 
            inc.id === message.data.incident_id 
              ? { ...inc, ...message.data } 
              : inc
          )
        );
        break;
      
      case 'notification':
        toast.info(message.data.title);
        break;
      
      default:
        break;
    }
  };

  // Auto-refresh every 30 seconds
  useEffect(() => {
    loadData();
    
    if (autoRefresh) {
      const interval = setInterval(loadData, 30000);
      return () => clearInterval(interval);
    }
  }, [loadData, autoRefresh]);

  // Request notification permission
  useEffect(() => {
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  // Filter alerts
  const filteredAlerts = alerts.filter(alert => {
    if (priorityFilter !== 'all' && alert.severity !== priorityFilter) return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (searchTerm && !alert.message.toLowerCase().includes(searchTerm.toLowerCase()) && 
        !alert.signature.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  }).sort((a, b) => {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
  });

  // Filter incidents by priority
  const filteredIncidents = incidents.filter(incident => {
    if (statusFilter !== 'all' && incident.status !== statusFilter) return false;
    if (searchTerm && !incident.signature.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !incident.asset_name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  }).sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

  const getSeverityColor = (severity) => {
    const colors = {
      low: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
      medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
      critical: 'bg-red-500/20 text-red-300 border-red-500/30'
    };
    return colors[severity] || colors.low;
  };

  const getStatusColor = (status) => {
    const colors = {
      active: 'bg-red-500/20 text-red-300 border-red-500/30',
      acknowledged: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      resolved: 'bg-green-500/20 text-green-300 border-green-500/30',
      new: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      in_progress: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      escalated: 'bg-purple-500/20 text-purple-300 border-purple-500/30'
    };
    return colors[status] || colors.active;
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds
    
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleString();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="realtime-dashboard">
      {/* Header with Real-Time Status */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Activity className="w-7 h-7 text-cyan-400" />
            Real-Time Operations Dashboard
          </h2>
          <p className="text-slate-400 mt-1">
            {companyName} • Live monitoring with event correlation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-800 px-3 py-2 rounded-lg">
            <Radio className={`w-4 h-4 ${wsConnected ? 'text-green-400 animate-pulse' : 'text-red-400'}`} />
            <span className="text-sm text-slate-300">
              {wsConnected ? 'Live' : 'Connecting...'}
            </span>
          </div>
          <Button
            onClick={loadData}
            variant="outline"
            size="sm"
            className="bg-slate-800 border-slate-700 text-white"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Real-Time Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Critical Alerts */}
          <Card className="bg-gradient-to-br from-red-500/10 to-red-600/10 border-red-500/30">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Critical Alerts</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{metrics.alerts.critical}</h3>
                </div>
                <AlertTriangle className="w-10 h-10 text-red-400" />
              </div>
            </CardContent>
          </Card>

          {/* High Priority Alerts */}
          <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/10 border-orange-500/30">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">High Priority</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{metrics.alerts.high}</h3>
                </div>
                <AlertCircle className="w-10 h-10 text-orange-400" />
              </div>
            </CardContent>
          </Card>

          {/* Active Incidents */}
          <Card className="bg-gradient-to-br from-cyan-500/10 to-cyan-600/10 border-cyan-500/30">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Active Incidents</p>
                  <h3 className="text-3xl font-bold text-white mt-1">
                    {metrics.incidents.new + metrics.incidents.in_progress}
                  </h3>
                </div>
                <Zap className="w-10 h-10 text-cyan-400" />
              </div>
            </CardContent>
          </Card>

          {/* Noise Reduction */}
          <Card className="bg-gradient-to-br from-green-500/10 to-green-600/10 border-green-500/30">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Noise Reduction</p>
                  <h3 className="text-3xl font-bold text-white mt-1">
                    {metrics.kpis.noise_reduction_pct.toFixed(1)}%
                  </h3>
                </div>
                <TrendingDown className="w-10 h-10 text-green-400" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm text-slate-400 mb-2 block">Priority Filter</label>
              <Select value={priorityFilter} onValueChange={setPriorityFilter}>
                <SelectTrigger className="bg-slate-900 border-slate-700 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700">
                  <SelectItem value="all">All Priorities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm text-slate-400 mb-2 block">Status Filter</label>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="bg-slate-900 border-slate-700 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700">
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="new">New</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm text-slate-400 mb-2 block">Search</label>
              <Input
                placeholder="Search alerts/incidents..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Real-Time Alerts List */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            Active Alerts ({filteredAlerts.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {filteredAlerts.length === 0 ? (
              <div className="text-center text-slate-400 py-8">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-400" />
                <p>No active alerts matching filters</p>
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 hover:border-cyan-500/30 transition-all"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={getSeverityColor(alert.severity)}>
                          {alert.severity.toUpperCase()}
                        </Badge>
                        <Badge className={getStatusColor(alert.status)}>
                          {alert.status}
                        </Badge>
                        <span className="text-xs text-slate-500">{alert.tool_source}</span>
                      </div>
                      <p className="text-white font-medium">{alert.signature}</p>
                      <p className="text-sm text-slate-400 mt-1">{alert.message}</p>
                      <p className="text-xs text-slate-500 mt-2">
                        {alert.asset_name} • {formatTime(alert.timestamp)}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      {/* Real-Time Incidents List */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            Correlated Incidents ({filteredIncidents.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {filteredIncidents.length === 0 ? (
              <div className="text-center text-slate-400 py-8">
                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-green-400" />
                <p>No incidents matching filters</p>
              </div>
            ) : (
              filteredIncidents.map((incident) => (
                <div
                  key={incident.id}
                  className="bg-slate-900/50 border border-slate-700 rounded-lg p-4 hover:border-cyan-500/30 transition-all"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={getSeverityColor(incident.severity)}>
                          {incident.severity.toUpperCase()}
                        </Badge>
                        <Badge className={getStatusColor(incident.status)}>
                          {incident.status}
                        </Badge>
                        {incident.priority_score && (
                          <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/30">
                            Priority: {incident.priority_score.toFixed(1)}
                          </Badge>
                        )}
                      </div>
                      <p className="text-white font-medium">{incident.signature}</p>
                      <p className="text-sm text-slate-400 mt-1">
                        {incident.asset_name} • {incident.alert_count} correlated alerts
                      </p>
                      {incident.tool_sources && incident.tool_sources.length > 0 && (
                        <p className="text-xs text-slate-500 mt-1">
                          Sources: {incident.tool_sources.join(', ')}
                        </p>
                      )}
                      <p className="text-xs text-slate-500 mt-2">
                        Created {formatTime(incident.created_at)}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RealTimeDashboard;

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
  AlertTriangle, XCircle
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
  });

  // Filter incidents by status
  const filteredIncidents = incidents.filter(incident => {
    if (statusFilter !== 'all' && incident.status !== statusFilter) return false;
    if (searchTerm && !incident.signature.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !incident.asset_name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

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
            {companyName} • Live monitoring with
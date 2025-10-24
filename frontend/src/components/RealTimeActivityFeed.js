import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Activity, Zap, AlertCircle, CheckCircle, UserPlus, PlayCircle, TrendingUp } from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';

const RealTimeActivityFeed = ({ companyId }) => {
  const [activities, setActivities] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);
  const maxActivities = 50; // Keep last 50 activities

  useEffect(() => {
    setupWebSocket();
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [companyId]);

  const setupWebSocket = () => {
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
    const wsUrl = backendUrl.replace('http', 'ws').replace('/api', '') + '/ws';
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      console.log('RealTimeActivityFeed WebSocket connected');
      setWsConnected(true);
    };
    
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        handleWebSocketMessage(message);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setWsConnected(false);
    };
    
    ws.onclose = () => {
      console.log('WebSocket disconnected, reconnecting in 3s...');
      setWsConnected(false);
      setTimeout(setupWebSocket, 3000);
    };
    
    wsRef.current = ws;
  };

  const handleWebSocketMessage = (message) => {
    const activityItem = createActivityFromMessage(message);
    if (activityItem) {
      setActivities(prev => {
        const newActivities = [activityItem, ...prev];
        return newActivities.slice(0, maxActivities); // Keep only last 50
      });
    }
  };

  const createActivityFromMessage = (message) => {
    const timestamp = new Date().toISOString();
    
    switch (message.type) {
      case 'demo_progress':
        return {
          id: `${timestamp}-demo-progress`,
          type: 'demo_progress',
          icon: <PlayCircle className="w-4 h-4" />,
          color: 'text-blue-400',
          bgColor: 'bg-blue-500/10',
          borderColor: 'border-blue-500/30',
          title: 'Generating Demo Data',
          message: `${message.data.current}/${message.data.total} alerts (${message.data.percentage}%)`,
          timestamp
        };
      
      case 'correlation_started':
        return {
          id: `${timestamp}-corr-start`,
          type: 'correlation_started',
          icon: <Zap className="w-4 h-4" />,
          color: 'text-cyan-400',
          bgColor: 'bg-cyan-500/10',
          borderColor: 'border-cyan-500/30',
          title: 'Correlation Started',
          message: message.data.message || 'Starting alert correlation...',
          timestamp
        };
      
      case 'correlation_progress':
        if (message.data.status === 'processing') {
          return {
            id: `${timestamp}-corr-proc`,
            type: 'correlation_progress',
            icon: <TrendingUp className="w-4 h-4" />,
            color: 'text-cyan-400',
            bgColor: 'bg-cyan-500/10',
            borderColor: 'border-cyan-500/30',
            title: 'Correlating Alerts',
            message: message.data.message || `Processing ${message.data.processed || 0}/${message.data.total || 0}`,
            timestamp
          };
        } else if (message.data.status === 'grouping_complete') {
          return {
            id: `${timestamp}-corr-group`,
            type: 'correlation_progress',
            icon: <CheckCircle className="w-4 h-4" />,
            color: 'text-green-400',
            bgColor: 'bg-green-500/10',
            borderColor: 'border-green-500/30',
            title: 'Grouping Complete',
            message: message.data.message || `Found ${message.data.incident_groups_count || 0} incident groups`,
            timestamp
          };
        }
        return null;
      
      case 'correlation_complete':
        return {
          id: `${timestamp}-corr-complete`,
          type: 'correlation_complete',
          icon: <CheckCircle className="w-4 h-4" />,
          color: 'text-green-400',
          bgColor: 'bg-green-500/10',
          borderColor: 'border-green-500/30',
          title: 'Correlation Complete',
          message: message.data.message || `Created ${message.data.incidents_created || 0} incidents`,
          timestamp
        };
      
      case 'incident_created':
        return {
          id: `${timestamp}-incident-${message.data.id}`,
          type: 'incident_created',
          icon: <AlertCircle className="w-4 h-4" />,
          color: 'text-orange-400',
          bgColor: 'bg-orange-500/10',
          borderColor: 'border-orange-500/30',
          title: 'Incident Created',
          message: `${message.data.signature || 'Unknown'} on ${message.data.asset_name || 'Unknown asset'}`,
          timestamp
        };
      
      case 'auto_decide_started':
        return {
          id: `${timestamp}-decide-start-${message.data.incident_id}`,
          type: 'auto_decide_started',
          icon: <Zap className="w-4 h-4" />,
          color: 'text-purple-400',
          bgColor: 'bg-purple-500/10',
          borderColor: 'border-purple-500/30',
          title: 'Auto-Decide Started',
          message: message.data.message || `Analyzing incident...`,
          timestamp
        };
      
      case 'auto_decide_progress':
        return {
          id: `${timestamp}-decide-prog-${message.data.incident_id}`,
          type: 'auto_decide_progress',
          icon: <Activity className="w-4 h-4" />,
          color: 'text-purple-400',
          bgColor: 'bg-purple-500/10',
          borderColor: 'border-purple-500/30',
          title: 'Processing Decision',
          message: message.data.message || 'Making decision...',
          timestamp
        };
      
      case 'incident_auto_executed':
        return {
          id: `${timestamp}-auto-exec-${message.data.incident_id}`,
          type: 'incident_auto_executed',
          icon: <PlayCircle className="w-4 h-4" />,
          color: 'text-green-400',
          bgColor: 'bg-green-500/10',
          borderColor: 'border-green-500/30',
          title: 'Runbook Executed',
          message: message.data.message || `Executed: ${message.data.runbook_name || 'Unknown runbook'}`,
          timestamp
        };
      
      case 'incident_auto_assigned':
        return {
          id: `${timestamp}-auto-assign-${message.data.incident_id}`,
          type: 'incident_auto_assigned',
          icon: <UserPlus className="w-4 h-4" />,
          color: 'text-blue-400',
          bgColor: 'bg-blue-500/10',
          borderColor: 'border-blue-500/30',
          title: 'Incident Assigned',
          message: message.data.message || `Assigned to ${message.data.technician_name || 'Unknown'}`,
          timestamp
        };
      
      case 'auto_decide_complete':
        return {
          id: `${timestamp}-decide-complete-${message.data.incident_id}`,
          type: 'auto_decide_complete',
          icon: <CheckCircle className="w-4 h-4" />,
          color: 'text-green-400',
          bgColor: 'bg-green-500/10',
          borderColor: 'border-green-500/30',
          title: 'Decision Complete',
          message: message.data.message || `Status: ${message.data.status || 'updated'}`,
          timestamp
        };
      
      default:
        return null;
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds
    
    if (diff < 5) return 'Just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return date.toLocaleTimeString();
  };

  return (
    <Card className="bg-slate-900 border-slate-700">
      <CardHeader>
        <CardTitle className="text-white text-lg flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          Real-Time Activity
          {wsConnected && (
            <Badge className="ml-auto bg-green-500/20 text-green-400 border-green-500/30">
              Live
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[400px] pr-4">
          {activities.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>Waiting for activity...</p>
            </div>
          ) : (
            <div className="space-y-3">
              {activities.map((activity) => (
                <div
                  key={activity.id}
                  className={`p-3 rounded-lg border ${activity.bgColor} ${activity.borderColor} transition-all animate-in slide-in-from-top duration-300`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`${activity.color} mt-0.5`}>
                      {activity.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <h4 className="text-white font-medium text-sm">
                          {activity.title}
                        </h4>
                        <span className="text-xs text-slate-400 whitespace-nowrap">
                          {formatTime(activity.timestamp)}
                        </span>
                      </div>
                      <p className="text-sm text-slate-300 mt-1">
                        {activity.message}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default RealTimeActivityFeed;

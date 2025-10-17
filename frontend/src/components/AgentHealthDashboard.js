import React, { useState, useEffect } from 'react';
import { api } from '../App';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Server, Activity, Clock, RefreshCw, CheckCircle, XCircle, 
  AlertCircle, Wifi, WifiOff, Loader 
} from 'lucide-react';
import { toast } from 'sonner';

const AgentHealthDashboard = ({ companyId }) => {
  const [agentHealth, setAgentHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    loadAgentHealth();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      loadAgentHealth(true);
    }, 30000);
    
    return () => clearInterval(interval);
  }, [companyId]);

  const loadAgentHealth = async (isAutoRefresh = false) => {
    if (!isAutoRefresh) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    
    try {
      const response = await api.get(`/companies/${companyId}/agent-health`);
      setAgentHealth(response.data);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Failed to load agent health:', error);
      if (!isAutoRefresh) {
        toast.error('Failed to load agent health');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const getPingStatusBadge = (status) => {
    const badges = {
      'Online': {
        icon: <Wifi className="w-4 h-4" />,
        className: 'bg-green-500/20 text-green-400 border-green-500/30'
      },
      'ConnectionLost': {
        icon: <WifiOff className="w-4 h-4" />,
        className: 'bg-amber-500/20 text-amber-400 border-amber-500/30'
      },
      'Inactive': {
        icon: <XCircle className="w-4 h-4" />,
        className: 'bg-red-500/20 text-red-400 border-red-500/30'
      }
    };
    
    const badge = badges[status] || badges['Inactive'];
    
    return (
      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-semibold border ${badge.className}`}>
        {badge.icon}
        {status}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader className="w-8 h-8 text-cyan-400 animate-spin mr-3" />
        <span className="text-slate-400">Loading agent health...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Agent Health Monitoring</h2>
          <p className="text-slate-400">
            Real-time SSM agent status for {agentHealth?.company_name}
          </p>
        </div>
        <div className="flex items-center gap-4">
          {lastUpdated && (
            <div className="text-sm text-slate-500">
              Last updated: {formatTimestamp(lastUpdated)}
            </div>
          )}
          <Button
            onClick={() => loadAgentHealth()}
            disabled={refreshing}
            variant="outline"
            className="border-slate-700 text-slate-300"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Status Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <Server className="w-8 h-8 text-cyan-400" />
              <div className="text-3xl font-bold text-white">
                {agentHealth?.total_instances || 0}
              </div>
            </div>
            <div className="text-sm text-slate-400">Total Instances</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <CheckCircle className="w-8 h-8 text-green-400" />
              <div className="text-3xl font-bold text-green-400">
                {agentHealth?.online_instances || 0}
              </div>
            </div>
            <div className="text-sm text-green-300">Online & Healthy</div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-red-500/10 to-rose-500/10 border-red-500/30">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <XCircle className="w-8 h-8 text-red-400" />
              <div className="text-3xl font-bold text-red-400">
                {agentHealth?.offline_instances || 0}
              </div>
            </div>
            <div className="text-sm text-red-300">Offline / Issues</div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-2">
              <Activity className="w-8 h-8 text-purple-400" />
              <div className="text-3xl font-bold text-white">
                {agentHealth?.online_instances > 0 
                  ? Math.round((agentHealth.online_instances / agentHealth.total_instances) * 100) 
                  : 0}%
              </div>
            </div>
            <div className="text-sm text-slate-400">Health Score</div>
          </CardContent>
        </Card>
      </div>

      {/* Instances List */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Instance Details</CardTitle>
          <CardDescription className="text-slate-400">
            SSM agent status and connectivity information
          </CardDescription>
        </CardHeader>
        <CardContent>
          {agentHealth?.instances && agentHealth.instances.length > 0 ? (
            <div className="space-y-3">
              {agentHealth.instances.map((instance) => (
                <div 
                  key={instance.instance_id}
                  className="p-5 bg-slate-800/50 border border-slate-700 rounded-lg hover:border-slate-600 transition-colors"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${
                        instance.is_online 
                          ? 'bg-green-500/20 text-green-400' 
                          : 'bg-red-500/20 text-red-400'
                      }`}>
                        {instance.is_online ? (
                          <CheckCircle className="w-6 h-6" />
                        ) : (
                          <XCircle className="w-6 h-6" />
                        )}
                      </div>
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="font-mono text-lg font-semibold text-white">
                            {instance.instance_id}
                          </span>
                          {getPingStatusBadge(instance.ping_status)}
                        </div>
                        {instance.computer_name && (
                          <div className="text-sm text-slate-400">
                            Computer Name: <span className="text-slate-300">{instance.computer_name}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-slate-500 mb-1">Last Ping</div>
                      <div className="text-slate-300 font-medium">
                        {formatTimestamp(instance.last_ping)}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Platform</div>
                      <div className="text-sm text-slate-300 font-medium">
                        {instance.platform_name || instance.platform_type}
                      </div>
                      <div className="text-xs text-slate-500">
                        {instance.platform_version}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">IP Address</div>
                      <div className="text-sm text-slate-300 font-mono">
                        {instance.ip_address || 'N/A'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Agent Version</div>
                      <div className="text-sm text-slate-300 font-mono">
                        {instance.agent_version}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Platform Type</div>
                      <div className="text-sm text-slate-300">
                        {instance.platform_type}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 mb-1">Connectivity</div>
                      <div className="flex items-center gap-2">
                        {instance.is_online ? (
                          <>
                            <Wifi className="w-4 h-4 text-green-400" />
                            <span className="text-sm text-green-400 font-medium">Connected</span>
                          </>
                        ) : (
                          <>
                            <WifiOff className="w-4 h-4 text-red-400" />
                            <span className="text-sm text-red-400 font-medium">Disconnected</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {!instance.is_online && (
                    <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-start gap-2">
                      <AlertCircle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-amber-400">
                        <strong>Troubleshooting:</strong> This instance hasn't responded to SSM pings. 
                        Check that the SSM agent is running and the IAM role has proper permissions.
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Server className="w-16 h-16 text-slate-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-slate-400 mb-2">
                No SSM Agents Found
              </h3>
              <p className="text-slate-500 mb-6">
                No instances with SSM agent detected for this company.
              </p>
              <div className="p-4 bg-slate-800/50 rounded-lg max-w-md mx-auto text-left">
                <h4 className="text-sm font-semibold text-white mb-2">To get started:</h4>
                <ol className="text-sm text-slate-400 space-y-1 list-decimal list-inside">
                  <li>Install SSM agent on your EC2 instances</li>
                  <li>Attach IAM role with SSM permissions</li>
                  <li>Wait 2-3 minutes for agent registration</li>
                  <li>Refresh this page to see your instances</li>
                </ol>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Monitoring Info */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <Activity className="w-5 h-5 mr-2 text-cyan-400" />
            About Agent Health Monitoring
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-slate-300">
          <div>
            <h4 className="font-semibold text-white mb-2">What is SSM Agent Health?</h4>
            <p className="text-sm text-slate-400">
              The SSM (AWS Systems Manager) agent runs on your EC2 instances and enables secure remote management 
              without VPN or SSH access. This dashboard shows real-time connectivity status for all managed instances.
            </p>
          </div>
          <div>
            <h4 className="font-semibold text-white mb-2">Status Indicators:</h4>
            <ul className="space-y-2 text-sm text-slate-400">
              <li className="flex items-center gap-2">
                <Wifi className="w-4 h-4 text-green-400" />
                <strong className="text-green-400">Online:</strong> Agent is connected and responding to pings
              </li>
              <li className="flex items-center gap-2">
                <WifiOff className="w-4 h-4 text-amber-400" />
                <strong className="text-amber-400">Connection Lost:</strong> Agent was recently online but not responding
              </li>
              <li className="flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-400" />
                <strong className="text-red-400">Inactive:</strong> Agent hasn't connected or is not installed
              </li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold text-white mb-2">Automatic Monitoring:</h4>
            <p className="text-sm text-slate-400">
              This dashboard refreshes every 30 seconds to provide real-time visibility into your infrastructure health.
              Use this information to identify connectivity issues before they impact your operations.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AgentHealthDashboard;

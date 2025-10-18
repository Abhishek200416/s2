import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  AlertCircle, Activity, Server, Clock, CheckCircle, 
  XCircle, TrendingUp, FileText, Shield, Bell
} from 'lucide-react';

const ClientPortal = () => {
  const [user, setUser] = useState(null);
  const [company, setCompany] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  
  // Data states
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [assets, setAssets] = useState([]);
  const [slaReport, setSlaReport] = useState(null);
  const [activities, setActivities] = useState([]);
  const [metrics, setMetrics] = useState(null);

  const API_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001/api';

  useEffect(() => {
    loadClientData();
  }, []);

  const loadClientData = async () => {
    try {
      const token = localStorage.getItem('token');
      const config = { headers: { Authorization: `Bearer ${token}` } };

      // Get current user
      const profileRes = await axios.get(`${API_URL}/profile`, config);
      setUser(profileRes.data);

      // Get company (client should have only one company)
      const companyId = profileRes.data.company_ids[0];
      if (companyId) {
        const companyRes = await axios.get(`${API_URL}/companies/${companyId}`, config);
        setCompany(companyRes.data);

        // Load all client data
        await Promise.all([
          loadIncidents(companyId, config),
          loadAlerts(companyId, config),
          loadAssets(companyId, config),
          loadSLAReport(companyId, config),
          loadActivities(companyId, config),
          loadMetrics(companyId, config)
        ]);
      }

      setLoading(false);
    } catch (error) {
      console.error('Error loading client data:', error);
      setLoading(false);
    }
  };

  const loadIncidents = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/incidents?company_id=${companyId}`, config);
      setIncidents(res.data);
      
      // Log activity
      await logActivity('view_incidents', 'Viewed incident list', 'incident', null);
    } catch (error) {
      console.error('Error loading incidents:', error);
    }
  };

  const loadAlerts = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/alerts?company_id=${companyId}`, config);
      setAlerts(res.data);
      
      // Log activity
      await logActivity('view_alerts', 'Viewed alert list', 'alert', null);
    } catch (error) {
      console.error('Error loading alerts:', error);
    }
  };

  const loadAssets = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/companies/${companyId}/assets`, config);
      setAssets(res.data || []);
    } catch (error) {
      console.error('Error loading assets:', error);
    }
  };

  const loadSLAReport = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/companies/${companyId}/sla-report?days=30`, config);
      setSlaReport(res.data);
    } catch (error) {
      console.error('Error loading SLA report:', error);
    }
  };

  const loadActivities = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/companies/${companyId}/activities?days=30`, config);
      setActivities(res.data || []);
    } catch (error) {
      console.error('Error loading activities:', error);
    }
  };

  const loadMetrics = async (companyId, config) => {
    try {
      const res = await axios.get(`${API_URL}/companies/${companyId}/client-metrics?days=30`, config);
      setMetrics(res.data);
    } catch (error) {
      console.error('Error loading metrics:', error);
    }
  };

  const logActivity = async (activityType, description, resourceType, resourceId) => {
    try {
      const token = localStorage.getItem('token');
      await axios.post(`${API_URL}/client-activities/log`, {
        activity_type: activityType,
        description: description,
        resource_type: resourceType,
        resource_id: resourceId
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
    } catch (error) {
      console.error('Error logging activity:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-amber-500',
      low: 'bg-slate-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getStatusColor = (status) => {
    const colors = {
      new: 'bg-blue-500',
      in_progress: 'bg-yellow-500',
      resolved: 'bg-green-500',
      escalated: 'bg-red-500'
    };
    return colors[status] || 'bg-gray-500';
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'Just now';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading your portal...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <div className="bg-slate-800/50 border-b border-cyan-500/20 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                {company?.name || 'Client Portal'}
              </h1>
              <p className="text-sm text-slate-400 mt-1">Welcome back, {user?.name}</p>
            </div>
            <button
              onClick={() => {
                localStorage.removeItem('token');
                window.location.href = '/login';
              }}
              className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 transition-all"
            >
              Logout
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-6 py-6">
        <div className="flex space-x-2 border-b border-slate-700">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'incidents', label: 'Incidents', icon: AlertCircle },
            { id: 'alerts', label: 'Alerts', icon: Bell },
            { id: 'assets', label: 'Assets', icon: Server },
            { id: 'sla', label: 'SLA Reports', icon: TrendingUp },
            { id: 'activity', label: 'Activity Log', icon: FileText }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 flex items-center space-x-2 border-b-2 transition-all ${
                activeTab === tab.id
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <tab.icon size={16} />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-6 pb-12">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Metrics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Active Incidents</p>
                    <p className="text-3xl font-bold text-white mt-2">
                      {incidents.filter(i => i.status !== 'resolved').length}
                    </p>
                  </div>
                  <AlertCircle className="text-orange-500" size={32} />
                </div>
              </div>

              <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Active Alerts</p>
                    <p className="text-3xl font-bold text-white mt-2">
                      {alerts.filter(a => a.status === 'active').length}
                    </p>
                  </div>
                  <Bell className="text-red-500" size={32} />
                </div>
              </div>

              <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">Monitored Assets</p>
                    <p className="text-3xl font-bold text-white mt-2">{assets.length}</p>
                  </div>
                  <Server className="text-blue-500" size={32} />
                </div>
              </div>

              <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-400">SLA Compliance</p>
                    <p className="text-3xl font-bold text-white mt-2">
                      {slaReport?.response_sla_compliance?.toFixed(0) || 0}%
                    </p>
                  </div>
                  <TrendingUp className="text-green-500" size={32} />
                </div>
              </div>
            </div>

            {/* Recent Incidents */}
            <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4">Recent Incidents</h3>
              <div className="space-y-3">
                {incidents.slice(0, 5).map(incident => (
                  <div key={incident.id} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                    <div className="flex-1">
                      <p className="font-medium">{incident.title}</p>
                      <p className="text-sm text-slate-400">{incident.description}</p>
                    </div>
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 rounded-full text-xs ${getStatusColor(incident.status)} text-white`}>
                        {incident.status}
                      </span>
                      <span className="text-sm text-slate-400">{formatTimestamp(incident.created_at)}</span>
                    </div>
                  </div>
                ))}
                {incidents.length === 0 && (
                  <p className="text-center text-slate-400 py-4">No incidents found</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Incidents Tab */}
        {activeTab === 'incidents' && (
          <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">All Incidents</h3>
            <div className="space-y-3">
              {incidents.map(incident => (
                <div key={incident.id} className="p-4 bg-slate-700/30 rounded-lg">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className={`px-3 py-1 rounded-full text-xs ${getStatusColor(incident.status)} text-white`}>
                          {incident.status}
                        </span>
                        <span className={`px-3 py-1 rounded-full text-xs ${getSeverityColor(incident.severity)} text-white`}>
                          {incident.severity}
                        </span>
                        <span className="text-sm text-slate-400">Priority: {incident.priority_score}</span>
                      </div>
                      <h4 className="font-semibold text-lg">{incident.title}</h4>
                      <p className="text-slate-400 mt-1">{incident.description}</p>
                      <div className="flex items-center space-x-4 mt-3 text-sm text-slate-500">
                        <span>Created: {formatTimestamp(incident.created_at)}</span>
                        {incident.assigned_to && <span>Assigned</span>}
                        {incident.correlated_alerts && (
                          <span>{incident.correlated_alerts.length} correlated alerts</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
              {incidents.length === 0 && (
                <p className="text-center text-slate-400 py-8">No incidents to display</p>
              )}
            </div>
          </div>
        )}

        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">All Alerts</h3>
            <div className="space-y-2">
              {alerts.map(alert => (
                <div key={alert.id} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(alert.severity)} text-white`}>
                        {alert.severity}
                      </span>
                      <span className="font-medium">{alert.asset_name}</span>
                    </div>
                    <p className="text-sm text-slate-400">{alert.message}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-slate-500">{alert.tool_source}</p>
                    <p className="text-xs text-slate-600">{formatTimestamp(alert.created_at)}</p>
                  </div>
                </div>
              ))}
              {alerts.length === 0 && (
                <p className="text-center text-slate-400 py-8">No alerts to display</p>
              )}
            </div>
          </div>
        )}

        {/* Assets Tab */}
        {activeTab === 'assets' && (
          <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Your Assets</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {assets.map((asset, idx) => (
                <div key={idx} className="p-4 bg-slate-700/30 rounded-lg">
                  <div className="flex items-center space-x-3 mb-3">
                    <Server className="text-cyan-500" size={24} />
                    <div>
                      <h4 className="font-semibold">{asset.instance_name || asset.instance_id}</h4>
                      <p className="text-sm text-slate-400">{asset.instance_type}</p>
                    </div>
                  </div>
                  <div className="space-y-1 text-sm">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Status:</span>
                      <span className={asset.state === 'running' ? 'text-green-400' : 'text-red-400'}>
                        {asset.state}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">IP:</span>
                      <span>{asset.private_ip || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">SSM Agent:</span>
                      <span className={asset.ssm_agent_online ? 'text-green-400' : 'text-red-400'}>
                        {asset.ssm_agent_online ? 'Online' : 'Offline'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
              {assets.length === 0 && (
                <p className="col-span-2 text-center text-slate-400 py-8">No assets found</p>
              )}
            </div>
          </div>
        )}

        {/* SLA Tab */}
        {activeTab === 'sla' && slaReport && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4">SLA Compliance Report (Last 30 Days)</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Response SLA</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Compliance:</span>
                      <span className="font-semibold text-green-400">
                        {slaReport.response_sla_compliance?.toFixed(1) || 0}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Avg Response Time:</span>
                      <span>{slaReport.avg_response_time_minutes?.toFixed(0) || 0} min</span>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Resolution SLA</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Compliance:</span>
                      <span className="font-semibold text-green-400">
                        {slaReport.resolution_sla_compliance?.toFixed(1) || 0}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Avg Resolution Time:</span>
                      <span>{slaReport.avg_resolution_time_minutes?.toFixed(0) || 0} min</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* SLA by Severity */}
            <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
              <h3 className="text-lg font-semibold mb-4">Compliance by Severity</h3>
              <div className="space-y-4">
                {slaReport.by_severity && Object.entries(slaReport.by_severity).map(([severity, data]) => (
                  <div key={severity} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                    <span className={`px-3 py-1 rounded-full text-xs ${getSeverityColor(severity)} text-white uppercase`}>
                      {severity}
                    </span>
                    <div className="flex space-x-6 text-sm">
                      <span>Response: {data.response_compliance?.toFixed(0) || 0}%</span>
                      <span>Resolution: {data.resolution_compliance?.toFixed(0) || 0}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Activity Log Tab */}
        {activeTab === 'activity' && (
          <div className="bg-slate-800/50 border border-cyan-500/20 rounded-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Activity Log</h3>
            <div className="space-y-2">
              {activities.map((activity, idx) => (
                <div key={idx} className="flex items-start space-x-3 p-3 bg-slate-700/30 rounded-lg">
                  <Activity className="text-cyan-500 mt-1" size={16} />
                  <div className="flex-1">
                    <p className="text-sm">{activity.description}</p>
                    <div className="flex items-center space-x-3 mt-1 text-xs text-slate-500">
                      <span>{activity.user_email}</span>
                      <span>•</span>
                      <span>{formatTimestamp(activity.timestamp)}</span>
                      {activity.resource_type && (
                        <>
                          <span>•</span>
                          <span>{activity.resource_type}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {activities.length === 0 && (
                <p className="text-center text-slate-400 py-8">No activity to display</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ClientPortal;
